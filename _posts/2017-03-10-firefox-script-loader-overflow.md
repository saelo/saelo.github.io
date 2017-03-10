---
layout: post
title:  "Exploiting a Cross-mmap Overflow in Firefox"
date:   2017-03-10
categories: bugs browser exploit
---

This post will explore how [CVE-2016-9066](https://www.mozilla.org/en-US/security/advisories/mfsa2016-89/#CVE-2016-9066), a simple but quite interesting (from an exploitation perspective) vulnerability in Firefox, can be exploited to gain code execution.

tl;dr an integer overflow in the code responsible for loading script tags leads to an out-of-bounds write past the end of an mmap chunk. One way to exploit this includes placing a JavaScript heap behind the buffer and subsequently overflowing into its meta data to create a fake free cell. It is then possible to place an ArrayBuffer instance inside another ArrayBuffer's inline data. The inner ArrayBuffer can then be arbitrarily modified, yielding an arbitrary read/write primitive. From there it is quite easy to achieve code execution. The full exploit can be found [here](https://github.com/saelo/foxpwn) and was tested against Firefox 48.0.1 on macOS 10.11.6. The bugzilla report can be found [here](https://bugzilla.mozilla.org/show_bug.cgi?id=1299686)

# The Vulnerability

The following [code](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/dom/base/nsScriptLoader.cpp#L2716) is used for loading the data for (external) script tags:

{% highlight C++ %}
result
nsScriptLoadHandler::TryDecodeRawData(const uint8_t* aData,
                                      uint32_t aDataLength,
                                      bool aEndOfStream)
{
  int32_t srcLen = aDataLength;
  const char* src = reinterpret_cast<const char *>(aData);
  int32_t dstLen;
  nsresult rv =
    mDecoder->GetMaxLength(src, srcLen, &dstLen);

  NS_ENSURE_SUCCESS(rv, rv);

  uint32_t haveRead = mBuffer.length();
  uint32_t capacity = haveRead + dstLen;
  if (!mBuffer.reserve(capacity)) {
    return NS_ERROR_OUT_OF_MEMORY;
  }

  rv = mDecoder->Convert(src,
                         &srcLen,
                         mBuffer.begin() + haveRead,
                         &dstLen);

  NS_ENSURE_SUCCESS(rv, rv);

  haveRead += dstLen;
  MOZ_ASSERT(haveRead <= capacity, "mDecoder produced more data than expected");
  MOZ_ALWAYS_TRUE(mBuffer.resizeUninitialized(haveRead));

  return NS_OK;
}
{% endhighlight %}

The code will be invoked by `OnIncrementalData` whenever new data has arrived from the server. The bug is a simple integer overflow, happening when the server sends more than 4GB of data. In that case, `capacity` will wrap around and the following call to `mBuffer.reserve` will not modify the buffer in any way. `mDecode->Convert` then writes data past the end of an 8GB buffer (data is stored as char16\_t in the browser), which will be backed by an mmap chunk (a common practice for very large chunks).

The patch is also similarly simple:

{% highlight diff %}
   uint32_t haveRead = mBuffer.length();
-  uint32_t capacity = haveRead + dstLen;
-  if (!mBuffer.reserve(capacity)) {
+
+  CheckedInt<uint32_t> capacity = haveRead;
+  capacity += dstLen;
+
+  if (!capacity.isValid() || !mBuffer.reserve(capacity.value())) {
     return NS_ERROR_OUT_OF_MEMORY;
   }
{% endhighlight %}

The bug doesn't look too promising at first. For one, it requires sending and allocating multiple gigabytes of memory. As we will see however, the bug can be exploited fairly reliably and the exploit completes within about a minute after opening the page on my 2015 MacBook Pro. We will now first explore how this bug can be exploited to pop a calculator on macOS, then improve the exploit to be more reliable and use less bandwidth afterwards (spoiler: we will use HTTP compression).

# Exploitation

Since the overflow happens past the end of an mmap region, our first concern is whether it is possible to reliably allocate something behind the overflown buffer. In contrast to some heap allocators, mmap (which can be thought of as a memory allocator provided by the kernel) is very deterministic: calling mmap twice will result in two consecutive mappings if there are no existing holes that could satisfy either of the two requests. You can try this for yourself using the following piece of code. Note that the result will be different depending on whether the code is run on Linux or macOS. The mmap region grows towards lower addresses on Linux while it grows towards higher ones on macOS. For the rest of this post we will focus on macOS. A similar exploit should be possible on Linux and Windows though.

{% highlight C %}
#include <sys/mman.h>
#include <stdio.h>

const size_t MAP_SIZE = 0x100000;       // 1 MB

int main()
{
    char* chunk1 = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    char* chunk2 = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    printf("chunk1: %p - %p\n", chunk1, chunk1 + MAP_SIZE);
    printf("chunk2: %p - %p\n", chunk2, chunk2 + MAP_SIZE);

    return 0;
}
{% endhighlight %}

The output of the above program tells us that we should be able to allocate something behind the overflowing buffer by simply mmap'ing memory until all existing holes are filled, then allocating one more memory chunk through mmap. To verify this we will do the following:

1. Load a HTML document which includes a script (payload.js, which will trigger the overflow) and asynchronously executes some JavaScript code (code.js, which implements step 3 and 5)

2. When the browser requests payload.js, have the server reply with a Content-Length of 0x100000001 but only send the first 0xffffffff bytes of the data

3. Afterwards, let the JavaScript code allocate multiple large (1GB) ArrayBuffers (memory won't necessarily be used until the buffers are actually written to)

4. Have the webserver send the remaining two bytes of payload.js

5. Check the first few bytes of every ArrayBuffer, one should contain the data sent by the webserver

To implement this, we will need some kind of synchronization primitive between the JavaScript code running in the browser and the webserver. For that reason I wrote a [tiny webserver](https://github.com/saelo/foxpwn/blob/master/server.py) on top of python's asyncio library which contains a handy [Event object](https://docs.python.org/3/library/asyncio-sync.html#event) for synchronization accross coroutines. Creating two global events makes it possible to signal the server that the client-side code has finished its current task and is now waiting for the server to perform the next step. The handler for `/sync` looks as follows:

{% highlight python %}
async def sync(request, response):
    script_ready_event.set()
    await server_done_event.wait()
    server_done_event.clear()

    response.send_header(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Length': '2'
    })

    response.write(b'OK')
    await response.drain()
{% endhighlight %}

On the client side, I used synchronous XMLHttpRequests to block script execution until the server has finished its part:

{% highlight JavaScript %}
function synchronize() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', location.origin + '/sync', false);
    // Server will block until the event has been fired
    xhr.send();
}
{% endhighlight %}

With that we can [implement](https://bugzilla.mozilla.org/show_bug.cgi?id=1299686#c2) the above scenario and we will see that indeed one of the ArrayBuffer objects now contains our payload byte at the start of its buffer. There is one small limitation though: we can only overflow with valid UTF-16, as that is what Firefox uses internally. We'll have to keep this in mind. What remains now is to find something more interesting to allocate instead of the ArrayBuffer that was overflown into.

## Hunting for Target Objects

Since `malloc` (and thus the `new` operator in C++) will at some point request more memory using mmap, anything allocated with those could potentially be of interest for our exploit. I went a different route though. I initially wanted to check whether it would be possible to overflow into JavaScript objects and for example corrupt the length of an array or something similar. I thus started to dig around the JavaScript allocators to see where JSObjects are stored. Spidermonkey (the JavaScript engine inside Firefox) stores JSObjects in two separate regions:

1. The tenured heap. Longer lived objects as well as a few selected object types are allocated here. This is a fairly classical heap that keeps track of free spots which it then reuses for future allocations.

2. The Nursery. This is a memory region that contains short-lived objects. Most JSObjects are first allocated here, then moved into the tenured heap if they are still alive during the next GC cycle (this includes updating all pointers to them and thus requires that the gargabe collector knows about all pointers to its objects). The nursery requires no free list or similar: after a GC cycle the nursery is simply declared free since all alive objects have been moved out of it.

For a more in depth discussion of Spidermonkey internals see [this](http://phrack.com/issues/69/14.html#article) phrack article.

Objects in the tenured heap are stored in containers called Arenas:

{% highlight C++ %}
/*
 * Arenas are the allocation units of the tenured heap in the GC. An arena
 * is 4kiB in size and 4kiB-aligned. It starts with several header fields
 * followed by some bytes of padding. The remainder of the arena is filled
 * with GC things of a particular AllocKind. The padding ensures that the
 * GC thing array ends exactly at the end of the arena:
 *
 * <----------------------------------------------> = ArenaSize bytes
 * +---------------+---------+----+----+-----+----+
 * | header fields | padding | T0 | T1 | ... | Tn |
 * +---------------+---------+----+----+-----+----+
 * <-------------------------> = first thing offset
 */
class Arena
{
    static JS_FRIEND_DATA(const uint32_t) ThingSizes[];
    static JS_FRIEND_DATA(const uint32_t) FirstThingOffsets[];
    static JS_FRIEND_DATA(const uint32_t) ThingsPerArena[];

    /*
     * The first span of free things in the arena. Most of these spans are
     * stored as offsets in free regions of the data array, and most operations
     * on FreeSpans take an Arena pointer for safety. However, the FreeSpans
     * used for allocation are stored here, at the start of an Arena, and use
     * their own address to grab the next span within the same Arena.
     */
    FreeSpan firstFreeSpan;

    // ...
{% endhighlight %}

The comment already gives a fairly good summary: [Arenas](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/gc/Heap.h#L450) are simply container objects inside which JavaScript objects of the [same size](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/gc/Heap.h#L83) are allocated. They are located inside a container object, the [Chunk structure](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/gc/Heap.h#L941), which is itself directly allocated through mmap. The interesting part is the `firstFreeSpan` member of the Arena class: it is the very first member of an Arena object (and thus lies at the beginning of an mmap-ed region), and essentially indicates the index of the first free cell inside this Arena. This is how a [FreeSpan](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/gc/Heap.h#L352) instance looks like:

{% highlight C++ %}
class FreeSpan
{
    uint16_t first;
    uint16_t last;

    // methods following
}
{% endhighlight %}

Both `first` and `last` are byte indices into the Arena, indicating the head of the freelist. This opens up an interesting way to exploit this bug: by overflowing into the `firstFreeSpan` field of an Arena, we may be able to allocate an object inside another object, preferably inside some kind of accessible inline data. We would then be able to modify the "inner" object arbitrarily.

This technique has a few benefits:

* Being able to allocate a JavaScript object at a chosen offset inside an Arena directly yields a memory read/write primitive as we shall see

* We only need to overflow 4 bytes of the following chunk and thus won't corrupt any pointers or other sensitive data

* Arenas/Chunks can be allocated fairly reliably just by allocating large numbers of JavaScript objects

As it turns out, ArrayBuffer objects up to a size of 96 bytes will have their data stored inline after the object header. They will also [skip the nursery](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/vm/ArrayBufferObject.cpp#L667) and thus be located inside an Arena. This makes them ideal for our exploit. We will thus

1. Allocate lots of ArrayBuffers with 96 bytes of storage

2. Overflow and create a fake free cell inside the Arena following our buffer

3. Allocate more ArrayBuffer objects of the same size and see if one of them is placed inside another ArrayBuffer's data (just scan all "old" ArrayBuffers for non-zero content)

## The Need for GC

Unfortunately, it's not quite that easy: in order for Spidermonkey to allocate an object in our target (corrupted) Arena, the Arena must have previously been marked as (partially) free. This means that we need to free at least one slot in each Arena. We can do this by deleting every 25th ArrayBuffer (since there are 25 per Arena), then forcing garbage collection.

Spidermonkey triggers garbage collection for a [variety](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/gc/GCRuntime.h#L201) of [reasons](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/public/GCAPI.h#L52). It seems the easiest one to trigger is `TOO_MUCH_MALLOC`: it is simply triggered whenever a certain number of bytes have been allocated through malloc. Thus, the following code suffices to trigger a garbage collection:

{% highlight JavaScript %}
function gc() {
    const maxMallocBytes = 128 * MB;
    for (var i = 0; i < 3; i++) {
        var x = new ArrayBuffer(maxMallocBytes);
    }
}
{% endhighlight %}

Afterwards, our target arena will be put onto the free list and our subsequent overwrite will corrupt it. The next allocation from the corrupted arena will then return a (fake) cell inside the inline data of an ArrayBuffer object.

## (Optional Reading) Compacting GC

Actually, it's a little bit more complicated. There exists a GC mode called compacting GC, which will move objects from [multiple partially filled arenas](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/jsgc.cpp#L1828) to fill holes in other arenas. This reduces internal fragmentation and helps freeing up entire Chunks so they can be returned to the OS. For us however, a compacting GC would be troublesome since it might fill the hole we created in our target arena. The following code is used to determine whether a compacting GC should be run:

{% highlight C++ %}
bool
GCRuntime::shouldCompact()
{
    // Compact on shrinking GC if enabled, but skip compacting in incremental
    // GCs if we are currently animating.
    return invocationKind == GC_SHRINK && isCompactingGCEnabled() &&
        (!isIncremental || rt->lastAnimationTime + PRMJ_USEC_PER_SEC < PRMJ_Now());
}
{% endhighlight %}

Looking at the code there should be ways to prevent a compacting GC from happening (e.g. by performing some animations). It seems we are lucky though: our `gc` function from above will trigger the following code path in Spidermonkey, thus preventing a compacting GC since the invocationKind will be `GC_NORMAL` instead of `GC_SHRINK`.

{% highlight C++ %}
bool
GCRuntime::gcIfRequested()
{
    // This method returns whether a major GC was performed.

    if (minorGCRequested())
        minorGC(minorGCTriggerReason);

    if (majorGCRequested()) {
        if (!isIncrementalGCInProgress())
            startGC(GC_NORMAL, majorGCTriggerReason);       // <-- we trigger this code path
        else
            gcSlice(majorGCTriggerReason);
        return true;
    }

    return false;
}
{% endhighlight %}

## Writing an Exploit

At this point we have all the pieces together and can actually write an exploit. Once we have created the fake free cell and allocated an ArrayBuffer inside of it, we will see that one of the previously allocated ArrayBuffers now contains data. An ArrayBuffer object in Spidermonkey looks roughly as follows:

{% highlight C++ %}
// From JSObject
GCPtrObjectGroup group_;

// From ShapedObject
GCPtrShape shape_;

// From NativeObject
HeapSlots* slots_;
HeapSlots* elements_;

// Slot offsets from TODO
static const uint8_t DATA_SLOT = 0;
static const uint8_t BYTE_LENGTH_SLOT = 1;
static const uint8_t FIRST_VIEW_SLOT = 2;
static const uint8_t FLAGS_SLOT = 3;
{% endhighlight %}

The `XXX_SLOT` constants determine the offset of the corresponding value from the start of the object. As such, the data pointer (`DATA_SLOT`) will be stored at `addrof(ArrayBuffer) + sizeof(ArrayBuffer)`.

We can now construct the following exploit primitives:

* Reading from an absolute memory address: we set the `DATA_SLOT` to the desired address and read from the inner ArrayBuffer

* Writing to an absolute memory address: same as above, but this time we write to the inner ArrayBuffer

* Leaking the address of a JavaScript Object: for that, we set the Object whose address we want to know as property of the inner ArrayBuffer, then read the address from the `slots_` pointer through our existing read primitive

## Process Continuation

To avoid crashing the browser process during the next GC cycle, we have to repair a few things:

* The ArrayBuffer following the *outer* ArrayBuffer in our exploit, as that one will have been corrupted by the *inner* ArrayBuffer's data.
    To fix this, We can simply copy another ArrayBuffer object into that location

* The Cell that was originally freed in our Arena now looks like a used Cell and will be treated as such by the collector, leading to a crash since it has been overwritten with other data (e.g. a FreeSpan instance).
    We can fix this by restoring the original firstFreeSpan field of our Arena to mark that Cell as free again.

This suffices to keep the browser alive after the exploit finishes.

## Summary

Putting everything together, the following steps will award us with an arbitrary read/write primitive:

0. Insert a script tag to load the payload and eventually trigger the bug.

1. Wait for the server to send up to 2GB + 1 bytes of data. The browser will
   now have allocated the final chunk that we will later overflow from.
   We try to fill the existing mmap holes using ArrayBuffer objects like
   we did for the very first PoC.

2. Allocate JavaScript Arenas (memory regions) containing ArrayBuffers of size 96
   (largest size so the data is still allocated inline behind the object) and hope
   one of them is placed right after the buffer we are about to overflow.
   Mmap allocates contiguous regions, so this can only fail if we don't allocate
   enough memory or if something else is allocated there.

3. Have the server send everything up to 0xffffffff bytes in total, completely
   filling the current chunk

4. Free one ArrayBuffer in every arena and try to trigger gargabe collection
   so the arenas are inserted into the free list.

5. Have the server send the remaining data. This will trigger the overflow
   and corrupt the internal free list (indicating which cells are unused) of
   one of the arenas. The freelist is modified such that the first free cell lies
   within the inline data of one of the ArrayBuffers contained in the Arena.

6. Allocate more ArrayBuffers. If everything worked so far, one of them will be
   allocated inside the inline data of another ArrayBuffer. Search for that
   ArrayBuffer.

7. If found, construct an arbitrary memory read/write primitive. We can
   now modify the data pointer of the inner ArrayBuffer, so this is quite easy.

8. Repair the corrupted objects to keep the process alive after our exploit is finished.

## Popping calc

What remains now is to somehow pop a calculator.

A simple way to run custom code is to [abuse the JIT region](https://github.com/saelo/jscpwn/blob/master/pwn.html#L45), however, this technique is (partially) [mitigated in Firefox](https://jandemooij.nl/blog/2015/12/29/wx-jit-code-enabled-in-firefox/). This can be bypassed given our exploitation primitives (e.g. by writing a small ROP chain and transferring control there), but this seemed to complicated for a simple PoC.

There are other Firefox-specific techniques to obtain code execution by abusing privileged JavaScript, but these require non-trivial modifications to the browser state (e.g. adding the [turn_off_all_security_so_that_viruses_can_take_over_this_computer](https://bugzilla.mozilla.org/show_bug.cgi?id=984012) preference).

I instead ended up using some standard CTF tricks to finish the exploit: looking for cross references to libc functions that accept a string as first argument (in this case strcmp), I found the implementation of [`Date.toLocalFormat`](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/jsdate.cpp#L2823) and noticed that it [converts its first argument from a JSString to a C-string](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/jsdate.cpp#L2849), which it then uses as [first argument for strcmp](https://github.com/mozilla/gecko-dev/blob/40ae52a2c349f978a462a38f770e4e35d49f6563/js/src/jsdate.cpp#L2721). So we can simply replaced the GOT entry for `strcmp` with the address of `system` and execute `data_obj.toLocaleFormat("open -a /Applications/Calculator.app");`. Done :)

# Improving the Exploit

At this point the basic exploit is already finished. This section will now describe how to make it more reliable and less bandwidth hungry.

## Adding Robustness

Up until now our exploit simply allocated a few very large ArrayBuffer instances (1GB each) to fill existing mmap holes, then allocated roughly another GB of js::Arena instances to overflow into. It thus assumed that the browsers heap operations are more or less deterministic during exploitation. Since this isn't necessarily the case, we'd like to make our exploit a little more robust.

A quick look at then implementation of the mozilla::Vector class (which is used to hold the script buffer) shows us that it uses `realloc` to double the size of its buffer when needed. Since jemalloc directly uses mmap for larger chunks, this leaves us with the following allocation pattern:

* mmap 1MB
* mmap 2MB, munmap previous chunk
* mmap 4MB, munmap previous chunk
* mmap 8MB, munmap previous chunk
* ...
* mmap 8GB, munmap previous chunk

Because the current chunk size will always be larger than the sum of all previous chunks sizes, this will result in a lot of free space preceding our final buffer. In theory, we could simply calculate the total sum of the free space, then allocate a large ArrayBuffer afterwards. In practice, this doesn't quite work since there will be other allocations after the server starts sending data and before the browser finishes decompressing the last chunk. Also jemalloc holds back a part of the freed memory for later usage. Instead we'll try to allocate a chunk as soon as it is freed by the browser. Here's what we'll do:

1. JavaScript code waits for the server using `sync`

2. The server sends all data up to the next power of two (in MB) and thus triggers exactly one call to realloc at the end. The browser will now free a chunk of a known size

3. The server sets the `server_done_event`, causing the JavaScript code to continue

4. JavaScript code allocates an ArrayBuffer instance of the same size as the previous buffer, filling the free space

5. This is repeated until we have send 0x80000001 bytes (thus forced the allocation of the final buffer)

This simple algorithm is implemented on the server side [here](https://github.com/saelo/foxpwn/blob/master/poc.py#L48) and on the client in [step 1](https://github.com/saelo/foxpwn/blob/master/code.js#L310). Using this algorithm, we can fairly reliably get an allocation behind our target buffer by spraying only a few megabytes of ArrayBuffer instances instead of multiple gigabytes.

## Reducing Network Load

Our current exploit requires sending 4GB of data over the network. That's easy to fix though: we'll use HTTP compression. The nice part here is that e.g. zlip [supports](https://docs.python.org/3.5/library/zlib.html#zlib.Compress.flush) "streamed" compression, which makes it possible to incrementally compress the payload. With this we just have to add each part of the payload to the zlib stream, then call flush on it to obtain the next compressed chunk of the payload and send that to the server. The server will uncompress this chunk upon receiving it and perform the desired action (e.g. perform one realloc step).

This is implemented in the `construct_payload` method in [poc.py](https://github.com/saelo/foxpwn/blob/master/poc.py#L30) and manages to reduce the size of the payload to about 18MB.

## About Resource Usage

At least in theory, the exploit requires quite a lot of memory:

* an 8GB buffer holding our "JavaScript" payload.
    Actually, it's more like 12 GB, since during the final realloc, the content of a 4GB buffer must be copied to a new 8GB buffer

* multiple (around 6GB) buffers allocated by JavaScript to fill the holes created by realloc

* around 256 MB of ArrayBuffers

However, since many of the buffers are never written to, they don't necessarily consume any physical memory. Moreover, during the final realloc, only 4GB of the new buffer
will be written to before the old buffer is freed, so really "only" 8 GB are required there.

That's still a lot of memory though. However, there are some technologies that will help reduce that number if physical memory becomes low:

* Memory compression (macOS): large memory regions can be compressed and swapped out. This is perfect for our use case since the 8GB buffer will be completely filled with zeroes. This effect can be observed in the Activity Monitor.app, which at some point shows more than 6 GB of memory as "compressed" during the exploit.

* Page deduplication (Windows, Linux): pages containing the same content are mapped copy-on-write (COW) and point to the same physical page (essentially reducing memory usage to 4KB).

CPU usage will also be quite high during peek times (decompression). However, CPU pressure could further be reduced by sending the payload in smaller chunks with delays in between (which would obviously increase the time it takes for the exploit to work though). This would also give the OS more time to compress and/or deduplicate the large memory buffers.

## Further Possible Improvements

There are a few sources of unreliability in the current exploit, mostly dealing with timing:

* During the sending of the payload data, if JavaScript runs the allocation before the browser has fully processed the next chunk, the allocations will "desyncronize". This would likely lead to a failed exploit.
   Ideally, JavaScript would perform the allocation as soon as the next chunk has been received and processed. Which may be possible to determine by observing CPU usage.

* If a garbage collection cycle runs after we have corrupted the FreeSpan but before we have fixed it, we crash

* If a compacting gargabe collection cycle runs after we have freed some of the ArrayBuffers but before we have triggered the overflow, the exploit fails as the Arena will be filled up again.

* If the fake free Cell happens to be placed inside the freed ArrayBuffer's cell, then our exploit will fail and the browser will crash during the next gargabe collection cycle. With 25 cells per arena this
   gives us a theoretical 1/25 chance to fail. However, in my experiments, the free cells were always located at the same offset (1216 bytes into the Arena), indicating that the state of the engine at the beginning of the exploit is fairly deterministic (at least regarding the state of the Arenas holding objects of size 160 bytes).

From my experience, the exploit runs pretty reliable (>95%) if the browser is not under heavy usage. The exploit still works if 10+ other tabs are open, but might fail if for example a large web application is currently loading.

# Conclusion

While the bug isn't ideal from an attacker's perspective, it still can be exploited fairly reliably and without too much bandwidth usage. It is interesting to see how various technologies (compression, same page merging, ...) can make a bug such as this one easier to exploit.

Thinking of ways to prevent exploitability of such a bug, a few things come to mind. One fairly generic mitigation are guard pages (a page leading to a segfault whenever accessed in some way). These would have to be allocated before or after every mmap allocated region and would thus protect against exploitation of linear overflows such as this one. They would, however, not protect against non-linear overflows such as [this bug](https://bugzilla.mozilla.org/show_bug.cgi?id=1287266). Another possibility would be to introduce internal mmap randomization to scatter the allocated regions throughout the address space (likely only effective on 64-bit systems). This would best be performed by the kernel, but could also be done in userspace.
