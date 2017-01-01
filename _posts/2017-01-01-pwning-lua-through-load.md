---
layout: post
title:  "Pwning Lua through 'load'"
date:   2017-01-01
categories: misc
---

In this post we'll take a look at how to exploit the `load` function in [Lua][lua].

The Lua interpreter provides an interesting function to Lua code: [`load`][load-api]. It makes it possible to load (and subsequently execute) precompiled Lua bytecode at runtime (which one can obtain either through `luac` or by using [`string.dump`][string-dump-api] on a function). This is interesting since not only does it require a parser for a binary format, but also allows execution of arbitrary bytecode. In fact, using [afl][afl-fuzzer] to fuzz the bytecode loader will yield hundreds of crashes within a few minutes. Even the documentation explicitly warns about this function: `Lua does not check the consistency of binary chunks. Maliciously crafted binary chunks can crash the interpreter`.

Unsurprisingly, it turned out that malicious bytecode cannot just crash the interpreter, but also allows for native code execution within the interpreter process. This was the motivation for the "read-eval-pwn loop" CTF challenge of [33C3 CTF][ctf].

Let's dig a bit deeper and find out what's causing the interpreter to crash.

The [Lua virtual machine][lua-vm] is fairly simple, supporting only 47 different opcodes. The Lua interpreter uses a register-based virtual machine. As such many opcodes have register indices as operands. Other resources (e.g. constants) are also referenced by index. Take for example the implementation of the ["LOADK"][loadk_opcode] opcode, which is used to load a Lua value from a function's [constant table][function_constant_table] (to which the variable `k` points in the following code):

{% highlight C %}
vmcase(OP_LOADK) {
    TValue *rb = k + GETARG_Bx(i);
    setobj2s(L, ra, rb);
    vmbreak;
}
{% endhighlight %}

We can see that there are no kinds of bounds checks. This is true for other opcodes as well (and also isn't the only source of crashes). This is of course a known fact, but there also doesn't seem to be a good solution for this (maybe apart from completely disabling `load`). See also [this][lua-mail] email to the Lua mailing list that I wrote some time ago and the replies, in particular [this one][lua-mail-reply].

Anyway, this looks like an interesting "feature" to write an exploit for.. ;)

Our plan will be to abuse the out-of-bounds indexing in the LOADK handler to inject custom objects into the virtual machine. The basic idea here is to allocate lots of strings containing fake [Lua values][lua_value] through the constant table of the serialized function, hoping one would be placed behind the constants array itself during deserialization. Afterwards we use a the LOADK opcode with an out-of-bounds index to load a fake value in one of those strings.

Note that this approach has one drawback though: it relies on the heap layout since it indexes behind the heap chunk that holds the constants. This is a source of unreliability. It may be possible to avoid this by scanning (in the bytecode) for a particular value (e.g. a certain integer value) which marks the start of the fake values, but this is left as an exercise for the reader... ;)

At this point there is a very simple exploit in certain scenarios: assuming the Lua interpreter was modified such that e.g. `os.execute` was present in the binary but not available to Lua code (which happens if one just comments out [this][disable-os.execute] line in the source code), then we can simply create a fake function value that points to the native implementation and call it with whatever shell command we want to execute. We can get the address of the interpreter code itself (assuming a shared object or PIE) through `tostring(load)`:

{% highlight Lua %}
> print(tostring(load))
"function: 0x41bcf0"
{% endhighlight %}

So what if we removed those functions entirely, and, to make it more interesting, also used clang's [control flow integrity][clang-cfi] on the binary so we couldn't immediately gain RIP control through a fake function object? How can we exploit that?

Let's start with an arbitrary read/write primitive:

1. We'll create a fake string object with it's length set to 0x7fffffffffffffff, allowing us to leak memory behind the string object itself (unfortunately, Lua treats the index into the string as unsigned long, so reading before the string isn't possible, but also not necessary)

2. Since strings are immutable, we'll also set up a fake table object (a combination of dict and list if you're familiar with python), allowing us to write Lua values to anywhere in memory by setting the [array][table_array] pointer to the desired address

Next, we notice that the interpreter makes use of the [`setjmp`][man-setjmp] mechanism to implement exceptions and [yielding][yield] inside coroutines. The setjmp API is an easy way to bypass CFI protection since it directly loads various registers, including the instruction pointer, from a memory chunk.

To finish our exploit we will thus allocate coroutines until one of them is placed after our faked string. We can then leak the address of the `jmpbuf` structure, modify it from inside the coroutine and call `yield`, causing the interpreter to jump to an arbitrary address with fully controlled `rsp` register and a few others. A short ROP chain will do the rest.

Find the full exploit, together with all files necessary to reproduce the CTF challenge [on my github][github-repo].

[lua]: https://lua.org
[load-api]: https://www.lua.org/manual/5.3/manual.html#pdf-load
[string-dump-api]: https://www.lua.org/manual/5.3/manual.html#pdf-string.dump
[afl-fuzzer]: http://lcamtuf.coredump.cx/afl/
[ctf]: https://33c3ctf.ccc.ac
[lua-vm]: https://github.com/dibyendumajumdar/ravi/blob/master/readthedocs/lua_bytecode_reference.rst
[loadk_opcode]: https://github.com/lua/lua/blob/08199ade4ace6addd63148df4c596d6b61def8cd/lvm.c#L807
[function_constant_table]: https://github.com/lua/lua/blob/08199ade4ace6addd63148df4c596d6b61def8cd/lobject.h#L420
[lua-mail]: http://lua-users.org/lists/lua-l/2016-12/msg00111.html
[lua-mail-reply]: http://lua-users.org/lists/lua-l/2016-12/msg00112.html
[lua_value]: https://github.com/lua/lua/blob/08199ade4ace6addd63148df4c596d6b61def8cd/lobject.h#L113
[disable-os.execute]: https://github.com/lua/lua/blob/08199ade4ace6addd63148df4c596d6b61def8cd/loslib.c#L388
[clang-cfi]: http://clang.llvm.org/docs/ControlFlowIntegrity.html
[table_array]: https://github.com/lua/lua/blob/08199ade4ace6addd63148df4c596d6b61def8cd/lobject.h#L502
[man-setjmp]: http://man7.org/linux/man-pages/man3/setjmp.3.html
[yield]: https://www.lua.org/manual/5.3/manual.html#pdf-coroutine.yield
[github-repo]: https://github.com/saelo/33c3ctf-repl
