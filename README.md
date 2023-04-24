This project is a simple exercise meant to serve as a sandbox to work with binary data files. The sample files included in the `data` directory are meant to serve as a source of truth. The `sample` file is a simple uint8_t binary data file generated during program execution that fills in each index with its own value - i.e., index 0 contains 00, index 1 contains 01, etc. - to serve as a simple, visible data source. The program ingests this file and stores its data in a buffer for later manipulation. At the current moment, the data is manipulated so that its assumed 6-byte header is stripped off of each portion of the data file as it is read into the buffer. 

This repo assumes several things: 

1. The `sample` data file is larger than the size of the buffer used to read its content
2. The `sample` data file contains smaller data packets - each of which has a 6-byte header
3. Each packet's 6-byte header needs to be stripped prior to the data being written out to another file

The application for this prototype is parsing a binary data file that contains multiple packets of data which need their headers stripped so that the file can be reassembled into its original raw form.

Compilation:

Run `make all` to generate the binary.

Execution:

Run `./bin/file-maker` to generate both the sample binary data file and its parsed, stripped version.

 


