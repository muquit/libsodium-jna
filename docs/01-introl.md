# Introduction

*libsodium-jna* is a java library that binds to @LIBSODIUM@ C crypto APIs with @JNA@ (JNA). I wrote it because I did not like any of the Java implementation of libsodium. I hope you will find this project useful and fun to use.

We use *libsodium-jna* in @OBIDOS@, an enterprise web application from my company, @SPENEGO@, to store and share sensitive information securely. Please check it out!

Bug reports, suggestions are always welcome!

If you add support to more libsodium APIs, please send me a pull request. If yo do so, please do not forget to update the documentation add unit tests. If you need to generate test vectors, please look at ```misc/gen_test_vectors.c```
