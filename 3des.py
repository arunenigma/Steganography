
# -*- coding: utf-8 -*-
# EECS 444: Computer Security Course Project
# Author: Arunprasath Shankar
# axs918@case.edu
# -*- ------------- -*-
# Steganography: Hiding data inside an audio file
# Alice sending secret message to Bob using Steganography..

import os
import sys
import wave         
import struct
import chilkat 
from pylab import *

# LSB hiding technique is used to embed secretText 
# into a specified input audio (WAV)
# input_audio_path is the path to a host WAV audio file in Alice Folder 
# stegano is the data to be embedded (can be any type, only the binary representation is used)
# output_audio_path is the path for the steganographed audio data to be written to Bob's Folder

crypt = chilkat.CkCrypt2()
success = crypt.UnlockComponent("True")
if (success != True):
    #  Unlock failed.
    print crypt.lastErrorText()
    sys.exit()

#  To get 3DES, set the algorithm = "des", and the
#  key length to 168 bits:
crypt.put_CryptAlgorithm("des")
crypt.put_KeyLength(168)

#  The encrypted output will be a hex-encoded string.
#  It is also possible to use "base64", "url" (for url-encoding), and other modes.
crypt.put_EncodingMode("hex")

#  "cbc" is for Cipher-Block-Chaining.
crypt.put_CipherMode("cbc")

#  for 3DES (and DES) the block-size is 8 bytes.
#  The IV may be set from an encoded string:
crypt.SetEncodedIV("0102030405060708","hex")

#  The secret key should have a length equal to the bit-strength of
#  the algorithm. In this case, we have 168-bit 3DES.  However,
#  with DES (and 3DES) the most significant bit of each key byte is
#  a parity bit, and therefore 168-bits really refers to a 192-bit key
#  where the 24 msb's are parity bits.  Our 3DES key should be 24 bytes in size.
crypt.SetEncodedKey("010203040506070801020304050607080102030405060708","hex")


#  3DES is a block encryption algorithm.  This means that output is always
#  a multiple of the algorithm's block size.  For 3DES, the block size is 8 bytes.
#  Therefore, if your input is not a multiple of 8 bytes, it will be padded.
#  There are several choices for padding, I have padded with SPACE (0x20) characters:
crypt.put_PaddingScheme(4)

#cipherText = crypt.encryptStringENC("arunprasath_shankar")
#print cipherText
#plainText = crypt.decryptStringENC(cipherText)
#print plainText


# saving output log to a file
class Logger(object):
	def __init__(self, filename="Default.log"):
		self.terminal = sys.stdout
		self.log = open(filename, "a")

	def write(self, message):
		self.terminal.write(message)
		self.log.write(message)

sys.stdout = Logger("/Users/arunprasathshankar/Desktop/3des_results.txt")

def lsb(input_audio_path, secret_text, output_audio_path):

    print 'encrypted secret text -->',secret_text
    secret_text_str = str(secret_text)
    # getting the equivalent ASCII code for the characters of the secretText
    stegano = struct.unpack("%dB" % len(secret_text_str), secret_text_str)
    print 'equivalent ASCII code for the characters of the secretText'
    print stegano
    print
    stegano_size = len(stegano)
    stegano_bits = stegano_to_bits((stegano_size,), 32)
    stegano_bits.extend(stegano_to_bits(stegano))
    
    input_audio = wave.open(input_audio_path, 'rb') 
    
    (nchannels, sampwidth, framerate, nframes, comptype, compname) = input_audio.getparams()
    print 'input audio parameters'
    print
    print 'nchannels -->',nchannels
    print 'sampwidth -->',sampwidth
    print 'framerate -->',framerate
    print 'nframes   -->',nframes
    frames = input_audio.readframes (nframes * nchannels)
    samples = struct.unpack_from ("%dh" % nframes * nchannels, frames)
    #print 'samples -->',samples
    import pylab as plt
    fig = plt.figure()
    plt.title('Input Audio Samples')
    plt.ylim( -32768, 32767 )
    plt.grid(True)
    plt.plot(samples, 'b-') # plot the samples with blue lines
    plt.draw()
    fig.savefig('../axs918/figures/input_audio_samples.png',dpi=fig.dpi)
    
    # Catching Exception
    if len(samples) < len(stegano_bits):
        raise OverflowError("The secret text provided is too big to fit into the cover audio! Failed to fit %d bits into %d bits of space." % (len(stegano_bits), len(samples))) 
    
    print "steganographing %s (%d samples) with %d bits of information." % (input_audio_path, len(samples), len(stegano_bits))
    
    encoded_samples = []
    
    stegano_position = 0
    n = 0
    for sample in samples:
        encoded_sample = sample
        
        if stegano_position < len(stegano_bits):
            encode_bit = stegano_bits[stegano_position]
            if encode_bit == 1:
                encoded_sample = sample | encode_bit
            else:
                encoded_sample = sample
                if sample & 1 != 0:
                    encoded_sample = sample - 1
                    
            stegano_position = stegano_position + 1
            
        encoded_samples.append(encoded_sample)
            
    encoded_audio = wave.open(output_audio_path, 'wb')
    encoded_audio.setparams( (nchannels, sampwidth, framerate, nframes, comptype, compname) )
    print 'encoded audio parameters'
    print
    #getparams(nchannels, sampwidth, framerate, nframes, comptype, compname)
    params = encoded_audio.getparams()
    print 'nchannels -->',params[0]
    print 'sampwidth -->',params[1]
    print 'framerate -->',params[2]
    print 'nframes   -->',params[3]
    #print 'samples   -->',encoded_samples
    fig = plt.figure()
    plt.title('Encoded Audio Samples')
    plt.ylim( -32768, 32767 )
    plt.grid(True)
    plt.plot(samples, 'r-') # plot the samples with blue lines
    plt.draw()
    fig.savefig('../axs918/figures/encoded_audio_samples.png',dpi=fig.dpi)
    

    encoded_audio.writeframes(struct.pack("%dh" % len(encoded_samples), *encoded_samples))

def stegano_to_bits(stegano, nbits=8):
    stegano_bits = []
    for byte in stegano:
        for i in range(0,nbits):
            stegano_bits.append( (byte & (2 ** i)) >> i )
    return stegano_bits
    
def recover_lsb(output_audio_path):
    # Simply collect the LSB from each sample
    steganoed_audio = wave.open(output_audio_path, 'rb') 
    
    (nchannels, sampwidth, framerate, nframes, comptype, compname) = steganoed_audio.getparams()
    frames = steganoed_audio.readframes (nframes * nchannels)
    samples = struct.unpack_from ("%dh" % nframes * nchannels, frames)
    
    # determine how many stegano bytes we should look for
    stegano_bytes = 0
    for (sample,i) in zip(samples[0:32], range(0,32)):
        stegano_bytes = stegano_bytes + ( (sample & 1) * (2 ** i))
    
    print "Recovering %d bytes of steganographed information from %s (%d samples)" % (stegano_bytes, output_audio_path, len(samples))
    
    secret_text = []
    
    for n in range(0, stegano_bytes):
        stegano_byte_samples = samples[32 + (n * 8) : 32+((n+1) * 8)]
        stegano_byte = 0
        for (sample, i) in zip(stegano_byte_samples, range(0,8)):
            stegano_byte = stegano_byte + ( (sample & 1) * (2**i) )
			
        secret_text.append(stegano_byte)
    print secret_text
    print
    f = open(hidden_data_dest,"w")
    wm_str = []
    for x in secret_text:
        wm_str.append( "".join(chr(x)))
    print wm_str
    print
    z = ''
    for i in wm_str:
        z+=i
    decryptedText = crypt.decryptStringENC(z)
        
    print decryptedText
    print
    f.write(decryptedText)
        

def embed_file(input_audio, hidden_file, output):
	f = open(hidden_file)
	hidden_data = f.read()
	lsb(input_audio, hidden_data, output)


# Visualizing the input and output wav audio files to see if there is any difference in
# waveforms due to embedding of secret text into wave file..

def show_wave_n_spec(speech):
    spf = wave.open(speech,'r')
    sound_info = spf.readframes(-1)
    sound_info = fromstring(sound_info, 'Int64')
    f = spf.getframerate()
    
    subplot(211)
    plot(sound_info)
    title('Wave from and spectrogram of %s' % path)

    subplot(212)
    spectrogram = specgram(sound_info, Fs = f, scale_by_freq=True,sides='default')

    show()
    spf.close()


def _test():
    import doctest
    doctest.testmod() 

if __name__ == "__main__":
    input_audio_path = '../axs918/alice/input.wav'
    secret_text_path = raw_input('Enter the secret message to be sent to Bob: ')
    #secret_text_path = '../axs918/alice/secret_text.txt'
    passwd = raw_input("Enter password to encrpt: ")
    crypt.put_PbesPassword(passwd)
    output = '../axs918/bob/output.wav'
    hidden_data_dest = '../axs918/bob/secret_text_from_bob.txt'


    encryptedText = crypt.encryptStringENC(secret_text_path) #cipherText
    if len(sys.argv) > 1:
        secret_text_path = sys.argv[1]
        if len(sys.argv) > 2:
            input_audio_path = sys.argv[2]
            if len(sys.argv) > 3:
                output_audio_path = sys.argv[3]

    lsb(input_audio_path, encryptedText, output)
    recover_lsb(output)

    path = input_audio_path
    show_wave_n_spec(path)

    path = output
    show_wave_n_spec(path)
    

    # calculating lines of code of Project 
    cur_path = os.getcwd()
    ignore_set = set(["chilkat.py"])

    loclist = []
    _test()

    for pydir, _, pyfiles in os.walk(cur_path):
	    for pyfile in pyfiles:
		    if pyfile.endswith(".py") and pyfile not in ignore_set:
			    totalpath = os.path.join(pydir, pyfile)
			    loclist.append( ( len(open(totalpath, "r").read().splitlines()),totalpath.split(cur_path)[1]) )

    for linenumbercount, filename in loclist: 
        print "%05d lines in %s" % (linenumbercount, filename)
    print "\nTotal: %s lines (%s)" %(sum([x[0] for x in loclist]), cur_path)
    



