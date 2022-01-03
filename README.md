# PNG Reader and Injector

## LICENSE

This project is based on Alexey Kutepov's project found here: https://gitlab.com/tsoding/png which is licensed as described in `original-license`. The modified code is licensed as described in `LICENSE`.

## Quick Start

### Build
```console
$ ./build.sh
````

### Usage
The program can be used in two different ways:

a) Read the content of a given PNG file
```console
$ ./png -r <input_png_file>
```

b) Inject a hidden message into a copy of a given PNG file
```console
$ ./png -i <input_png_file> <output_png_file> <message_to_inject>
```

A test image `PNG_transparency_demonstration_1.png` is provided to get started.

## References

- PNG specification: http://www.libpng.org/pub/png/spec/1.2/PNG-Contents.html
- Test image was taken from here: https://en.wikipedia.org/wiki/Portable_Network_Graphics#/media/File:PNG_transparency_demonstration_1.png
