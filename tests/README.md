# Tests

This requires a host-build of libkyrka in combination with sanitizers.

```
$ make clean && make dist-clean
$ env SANITIZE=1 ./dist-build/host-build.sh
$ make -C tests
$ cd tests && ./obj/test-api
```

The framework code is built into a library that is linked into each
of the invididual tests that reside under the **tests** directory.
