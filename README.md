recoverStarWriterDocument
=========================

recoverStarWriterDocument recovers lost passwords of StarWriterDocuments. It is optimized for multi core using OpenMP, but works also as a single thread, if compiled without OpenMP support.


1. Extract StarWriterDocument from ole file, e.g. with libolecf's olecfexport
2. Adjust maximum password length in Makefile
3. Run recoverStarWriterDocument, e.g. like
    `./recoverStarWriterDocument myfile.sdw.export/StarWriterDocument/StreamData.bin` 
