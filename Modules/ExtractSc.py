#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse

if __name__ in '__main__':
    parser = argparse.ArgumentParser( description = 'Extract a position independent shellcode from an executable.' )
    parser.add_argument( 'pepath', help = 'Path to the portable executable containing the shellcode.', type = str )
    parser.add_argument( 'scpath', help = 'Path to write the extracted shellcode.', type = argparse.FileType( 'wb+' ) )
    args = parser.parse_args()

    # Parse the portable executable
    pe = pefile.PE( args.pepath )

    # We have too many sections. Abort!
    if len( pe.sections ) != 1:
        # Raise an error to notify there has been an issue
        raise Exception( 'There should only be 1 section, there is currently {}'.format( len( pe.sections ) ) );

    # Extract the section from the PE
    code = pe.sections[ 0 ].get_data()

    # Find the mark from the shellcode
    offs = code.find( b'CODE-END' )

    # No marker was found
    if offs is None or offs == 0:
        raise Exception( 'The end of code marker is missing from the executable.' )

    # Extract the code up until the offset of the marker
    code = code[ : offs ]

    # Write the code to a file
    args.scpath.write( code );