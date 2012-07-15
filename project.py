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


# I have used PBES1 Password-Based Encryption (PBE) according to the PKCS #5 v2.0: 
# Password-Based Cryptography Standard (published by RSA Laboratories) which is 
# based on the PBKDF1 function and an underlying block cipher such as RC2, DES, etc.

#  Set properties for PBES1 encryption:
crypt = chilkat.CkCrypt2()

success = crypt.UnlockComponent("True")
if (success != True):
    print crypt.lastErrorText()
    sys.exit()

crypt.put_CryptAlgorithm("pbes1")

#  Set the underlying PBE algorithm (and key length):
#  For PBES1, the underlying algorithm must be either
#  56-bit DES or 64-bit RC2
#  (this is according to the PKCS#5 specifications at
#  http://www.rsa.com/rsalabs/node.asp?id=2127)

crypt.put_PbesAlgorithm("des") #we can also rc2 instead of des
crypt.put_KeyLength(56) # if rc2 is used, it is 64 instead of 56 bit
# crypt.put_KeyLength(168) for 3 DES Encryption
# The salt for PBKDF1 is always 8 bytes:
crypt.SetEncodedSalt("0102030405060708","hex")

#  A higher iteration count makes the algorithm more
#  computationally expensive and therefore exhaustive
#  searches (for breaking the encryption) is more difficult:
crypt.put_IterationCount(1024)

#  A hash algorithm needs to be set for PBES1:
crypt.put_HashAlgorithm("md5") # we can also use sha1 instead of md5

#  Indicate that the encrypted bytes should be returned
#  as a hex string:
crypt.put_EncodingMode("hex")

# saving output log to a file
class Logger(object):
	def __init__(self, filename="Default.log"):
		self.terminal = sys.stdout
		self.log = open(filename, "a")

	def write(self, message):
		self.terminal.write(message)
		self.log.write(message)

sys.stdout = Logger("/Users/arunprasathshankar/Desktop/project_results.txt")

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
    