# Title:       Project 2 - Automated File Recovery
# Description: Takes a disk image, locates file signatures, properly recovers user generated 
#              files without corruption, and generates a SHA-256 hash for each recovered file
# Authors:     Adia Foster (azf0046), Mary Mitchell (mem0250), and Vicki McLendon (vlm0013)
# Course:      COMP5350 - Digital Forensics
# Due Date:    5 November 2022
# Run:         python3 FileRecovery.py Project2.dd (Where Project2.dd can be any disk image)
# Sources:     https://stackoverflow.com/questions/34687516/how-to-read-binary-files-as-hex-in-python
#              https://stackoverflow.com/questions/3730964/python-script-execute-commands-in-terminal

import math
import os
import sys

# GLOBAL VARIABLES

# Notes for signatures: AVI is the first 8 hex characters of the signature, which is generally
#                       followed by the file size and then the rest of the signature comes after that
signatures = {'MPG': '000001b3', 'PDF': '25504446', 'BMP': '424d', 'GIF87a': '474946383761',
    'GIF89a': '474946383961', 'JPG': 'ffd8ff', 'DOCX': '504b030414000600', 'AVI': '52494646',
    'PNG': '89504e470d0a1a0a' }

# Notes for trailers/footers: for some of the shorter trailers/footers, we added trailing zeros to make sure that 
#                             the actual end of the file is found and not false positives (especially for pdfs which
#                             can have multiple eofs)
trailers = {'MPG1': '000001b7', 'MPG2': '000001b9', 'PDF1': '0d2525454f460d000000', 'PDF2': '0d0a2525454f460d0a000000',
    'PDF3': '0a2525454f460a000000', 'PDF4': '0a2525454f46000000', 'GIF': '003b000000', 'JPG': 'ffd9000000',
    'DOCX': '504b0506', 'PNG': '49454e44ae426082'}

# SUPPORTING METHODS

# openDiskImage: opens the disk image, gets the contents of it, and converts them to hexadecimal
def openDiskImage(inputDisk):
    print('Opening disk image...')

    # Open the disk, get the contents, and convert to hex
    with open(inputDisk, 'rb') as diskImage:
        hexData = diskImage.read().hex()
    print('Disk contents collected...')
    diskImage.close()

    print('Disk image closed...\n')
    # Return the hex contents
    return hexData

# locateAndRecoverFiles: loops through our signatures dictionary and for each signature finds the corresponding files 
#                        on the disk image and recovers them
def locateAndRecoverFiles(diskContents):
    print('Begin looking for file signatures (this process can take a minute or two)...')
    # Initialize the number of files currently found 
    numFilesFound = 0

    # Go through all of the file signatures that we want to find on the disk
    for sig in signatures:
        # Find the file signature in the unsearched contents of the disk
        searchLocation = 0 # Initially we want to start looking at the beginning of the disk (index 0)
        sigLocation = diskContents.find(signatures[sig])

        # While there are still file signatures of type sig loop through this
        while sigLocation != -1:
            # Check which signature has been found
            if sig == 'MPG':
		# Check that the signature is at the beginning of a sector and is not just part of file contents
                if (sigLocation % 512) == 0:
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

		    # Check for one of the footers that mark the end of the file
                    eof = diskContents.find(trailers['MPG1'], sigLocation)
                    if eof == -1: # If the first footer is not found then it must have the second footer type
                        eof = diskContents.find(trailers['MPG2'], sigLocation) 
                    eof = eof + 7 # Add 7 to get the index of the last character of the trailer/footer
					
                    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.mpg' 
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2) 
                    endOffset = int(math.ceil(eof / 2))
                    fileSize = endOffset - startOffset
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ") 
                    print('End Offset: ' + str(hex(endOffset)))

		    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next mpg file to the end of this file so we don't keep coming back to the current file
                    searchLocation = eof

                # If the signature is not at the start of a sector then move the search location past it 
                else:
                    searchLocation = sigLocation + 8

            elif sig == 'PDF':
                # Check that the signature is at the beginning of a sector and is not just part of file contents
                if (sigLocation % 512) == 0:
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

		    # Check for one of the footers that mark the end of the file
                    eof = diskContents.find(trailers['PDF1'], sigLocation)
                    endOffset = 13 # Length of footer (not including trailing zeros that were added)
                    if eof == -1: # If the first footer is not found then it must have one of the other footer type
                        eof = diskContents.find(trailers['PDF2'], sigLocation) 
                        endOffset = 17 # Length of footer (not including trailing zeros that were added)
                    if eof == -1:
                        eof = diskContents.find(trailers['PDF3'], sigLocation) 
                        endOffset = 13 # Length of footer (not including trailing zeros that were added)
                    if eof == -1:
                        eof = diskContents.find(trailers['PDF4'], sigLocation) 
                        endOffset = 11 # Length of footer (not including trailing zeros that were added)
                    endOffset = endOffset + eof

		    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.pdf'
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2)
                    endOffset = int(math.ceil(endOffset / 2))
                    fileSize = endOffset - startOffset
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ")
                    print('End Offset: ' + str(hex(endOffset)))

		    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next pdf file to the end of this file so we don't keep coming back to the current file
                    searchLocation = eof

                # If the signature is not at the start of a sector then move the search location past it
                else:
                    searchLocation = sigLocation + 8

            elif sig == 'BMP':
                # Check that the signature is at the beginning of a sector and the reserved bits are present
                # Since the bmp signature is so short, we check the reserved bits as well to be sure it is an actual file signature
                if (sigLocation % 512) == 0 and (diskContents[(sigLocation + 12):(sigLocation + 20)] == '00000000'):
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

                    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.bmp'
		    # Get the file size which is the next four bytes after the signature (little endian order)
                    fileSize = (str(diskContents[(sigLocation + 10):(sigLocation + 12)]) + str(diskContents[(sigLocation + 8):(sigLocation + 10)]) +
                        str(diskContents[(sigLocation + 6):(sigLocation + 8)]) + str(diskContents[(sigLocation + 4):(sigLocation + 6)]))
                    fileSize = int(fileSize, 16) # Convert the size from hex to decimal
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2)
                    endOffset = startOffset + fileSize
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ")
                    print('End Offset: ' + str(hex(endOffset)))

                    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next bmp file to the end of this file so we don't keep coming back to the current file
                    searchLocation = sigLocation + fileSize

                # If the signature is not at the start of a sector then move the search location past it
                else:
                    searchLocation = sigLocation + 4

            elif sig == 'GIF87a':
                # Check that the signature is at the beginning of a sector and is not just part of file contents
                if (sigLocation % 512) == 0:
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

		    # Check for the footer that marks the end of the file
                    eof = diskContents.find(trailers['GIF'], sigLocation)
                    eof = eof + 3 # Add 3 to get the index of the last character of the trailer/footer (not including trailing zeros that were added)

		    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.gif'
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2)
                    endOffset = int(math.ceil(eof / 2))
                    fileSize = endOffset - startOffset
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ")
                    print('End Offset: ' + str(hex(endOffset)))

		    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next gif file to the end of this file so we don't keep coming back to the current file
                    searchLocation = eof

                # If the signature is not at the start of a sector then move the search location past it
                else:
                    searchLocation = sigLocation + 12

            elif sig == 'GIF89a':
                # Check that the signature is at the beginning of a sector and is not just part of file contents
                if (sigLocation % 512) == 0:
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

		    # Check for the footer that marks the end of the file
                    eof = diskContents.find(trailers['GIF'], sigLocation)
                    eof = eof + 3 # Add 3 to get the index of the last character of the trailer/footer (not including trailing zeros that were added)

		    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.gif'
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2)
                    endOffset = int(math.ceil(eof / 2))
                    fileSize = endOffset - startOffset
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ")
                    print('End Offset: ' + str(hex(endOffset)))

		    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next gif file to the end of this file so we don't keep coming back to the current file
                    searchLocation = eof

                # If the signature is not at the start of a sector then move the search location past it
                else:
                    searchLocation = sigLocation + 12

            elif sig == 'JPG':
                # Check that the signature is at the beginning of a sector and is not just part of file contents
                if (sigLocation % 512) == 0:
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

		    # Check for the footer that marks the end of the file
                    eof = diskContents.find(trailers['JPG'], sigLocation)
                    eof = eof + 3 # Add 3 to get the index of the last character of the trailer/footer (not including trailing zeros that were added)

		    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.jpg'
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2)
                    endOffset = int(math.ceil(eof / 2))
                    fileSize = endOffset - startOffset
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ")
                    print('End Offset: ' + str(hex(endOffset)))

		    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next jpg file to the end of this file so we don't keep coming back to the current file
                    searchLocation = eof

                # If the signature is not at the start of a sector then move the search location past it
                else:
                    searchLocation = sigLocation + 6

            elif sig == 'DOCX':
                # Check that the signature is at the beginning of a sector and is not just part of file contents
                if (sigLocation % 512) == 0:
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

		    # Check for the footer that marks the end of the file
                    eof = diskContents.find(trailers['DOCX'], sigLocation)
                    eof = eof + 43 # Add 43 to get the index of the last character of the trailer/footer and the additional 18 bytes

		    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.docx'
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2)
                    endOffset = int(math.ceil(eof / 2))
                    fileSize = endOffset - startOffset
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ")
                    print('End Offset: ' + str(hex(endOffset)))

		    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next docx file to the end of this file so we don't keep coming back to the current file
                    searchLocation = eof

                # If the signature is not at the start of a sector then move the search location past it
                else:
                    searchLocation = sigLocation + 16

            elif sig == 'AVI':
                # Check that the signature is at the beginning of a sector and the last part of the head is present 
                if (sigLocation % 512) == 0 and (diskContents[(sigLocation + 16):(sigLocation + 32)] == '415649204c495354'):
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

                    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.avi'
		    # Get the file size which is the next four bytes after the signature (little endian order)
                    fileSize = (str(diskContents[(sigLocation + 14):(sigLocation + 16)]) + str(diskContents[(sigLocation + 12):(sigLocation + 14)]) +
                        str(diskContents[(sigLocation + 10):(sigLocation + 12)]) + str(diskContents[(sigLocation + 8):(sigLocation + 10)])) 
                    fileSize = int(fileSize, 16) + 8 # Convert from hex to decimal and add 8 because the size given by the header is off by 8 bytes...?
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2)
                    endOffset = startOffset + fileSize
		    # Print file information
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ")
                    print('End Offset: ' + str(hex(endOffset)))

                    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next docx file to the end of this file so we don't keep coming back to the current file
                    searchLocation = sigLocation + fileSize

                # If the signature is not at the start of a sector then move the search location past it
                else:
                    searchLocation = sigLocation + 32

            elif sig == 'PNG':
                # Check that the signature is at the beginning of a sector and is not just part of file contents
                if (sigLocation % 512) == 0:
                    print()
                    # If the signature found is a header, then increment the number of files found 
                    numFilesFound = numFilesFound + 1

		    # Check for the footer that marks the end of the file
                    eof = diskContents.find(trailers['PNG'], sigLocation)
                    eof = eof + 15 # Add 15 to get the index of the last character of the trailer/footer 

		    # Calculate file info and print it
                    fileName = 'File' + str(numFilesFound) + '.png'
                    # Since the disk contents are in hex we divided by 2 because 1 byte = 2 hex characters
                    # This gives us the decimal offset that you would find on something like ActiveDiskEditor
                    startOffset = int(sigLocation / 2)
                    endOffset = int(math.ceil(eof / 2))
                    fileSize = endOffset - startOffset
                    print(fileName, end = ', ')
                    print('Start Offset: ' + str(hex(startOffset)), end = ", ")
                    print('End Offset: ' + str(hex(endOffset)))

		    # Recover file using the file info we calculated and get SHA-256 hash
                    recoveryCommand = 'dd if=' + str(sys.argv[1]) + ' of=' + str(fileName) + ' bs=1 skip=' + str(startOffset) + ' count=' + str(fileSize)
                    os.system(recoveryCommand)
                    hashCommand = 'sha256sum ' + str(fileName)
                    print('SHA-256', end = ': ')
                    sys.stdout.flush() # Just helps with the print statements
                    os.system(hashCommand)

                    # Move starting search location for the next docx file to the end of this file so we don't keep coming back to the current file
                    searchLocation = eof

                # If the signature is not at the start of a sector then move the search location past it
                else:
                    searchLocation = sigLocation + 16

            # Try to find the next signature starting starting wherever the last signature was found so as not to get duplicates
            sigLocation = diskContents.find(signatures[sig], searchLocation)

    print('Done locating file signatures...\n')
    print('Total number of files found: ' + str(numFilesFound))

# MAIN METHOD
def main():
    print('=================== STARTING AUTOMATED FILE RECOVERY PROGRAM ===================')
    # Get the disk image from the command line arguements
    inputDisk = sys.argv[1]

    # Open the disk and get its contents
    diskContents = openDiskImage(inputDisk)

    # With the disk contents, locate the file signatures and recover the files
    locateAndRecoverFiles(diskContents)
    
if __name__ == "__main__":
    main()
