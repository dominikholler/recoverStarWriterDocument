recoverStarWriterDocument
=========================

recoverStarWriterDocument recovers lost passwords of StarWriterDocuments. If compiled with OpenMP support, a multi core optimized implementation is used; without OpenMP support, a single core optimized implementation is used.


1. Extract StarWriterDocument from SDW file, e.g. with libolecf's olecfexport
2. If using multi core optimization, adjust maximum password length in Makefile
3. Run recoverStarWriterDocument, e.g. like
    `./recoverStarWriterDocument myfile.sdw.export/StarWriterDocument/StreamData.bin` 
