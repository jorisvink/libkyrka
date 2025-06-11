# Tests

This requires a host-build of libkyrka in combination with sanitizers.

You need lcov and genhtml installed on your system.

```
$ make clean && make dist-clean
$ env COVERAGE=1 SANITIZE=1 ./dist-build/host-build.sh
$ cd tests && make coverage
```

The coverage HTML report can be found under the **coverage_html** directory.

The framework code is built into a library that is linked into each
of the invididual tests that reside under the **tests** directory.
