//
//  Cryptor.m
//  CryptoBluetooth
//
//  Created by Alexey on 5/06/2016.
//  Copyright © 2016 Alexey Zhilnikov. All rights reserved.
//

#import "Cryptor.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation Cryptor

static UInt8 const keyChainID[] = "au.com.companyname.publickey";
static CFIndex const keyChainIDLength = sizeof(keyChainID);

// Initialization vector for encryption/decryption operation in CBC mode
static NSString *const iv = @"company0";

// Key for encryption/decryption
static uint8_t const key[] = {0x1E, 0x37, 0x51, 0x6E, 0xF3, 0x81, 0x33, 0x63,
                              0xBB, 0x72, 0xE6, 0x2C, 0x5F, 0x7B, 0x91, 0xF6,
                              0x1C, 0x55, 0x70, 0xC8, 0xA3, 0x81, 0x24, 0x03};

// Singleton
+ (Cryptor *)sharedStore
{
    static Cryptor *cryptor = nil;
    
    if (nil == cryptor)
        cryptor = [[super allocWithZone:nil] init];
    
    return cryptor;
}

+ (instancetype)allocWithZone:(struct _NSZone *)zone
{
    return [self sharedStore];
}

- (NSData *)cryptData:(NSData *)data withOperation:(BOOL)encryption
{
    // Allocate a buffer to store the result
    uint8_t *dataOut = malloc(data.length);
    
    // Number of result bytes
    size_t dataOutMoved;
    
    // Pointer to the result
    NSData *decryptedData = nil;
    
    // Operation type
    CCOperation operation = encryption ? kCCEncrypt : kCCDecrypt;
    
    // Decrypt input data
    CCCryptorStatus status = CCCrypt(operation,
                                     kCCAlgorithm3DES,
                                     0,
                                     key,
                                     kCCKeySize3DES,
                                     [iv UTF8String],
                                     data.bytes,
                                     data.length,
                                     dataOut,
                                     data.length,
                                     &dataOutMoved);
    
    if ((kCCSuccess == status) && (dataOutMoved == data.length))
        // Convert result into NSData
        decryptedData = [[NSData alloc] initWithBytes:dataOut
                                               length:dataOutMoved];
    
    // Release memory
    free(dataOut);
    
    return decryptedData;
}

// Update old certificate by a new one
- (void)setCertificate:(NSData *)derData
{
    if (nil != derData)
    {
        [self deletePublicKeyFromKeyChain];
        [self setPublicKeyFromCertificate:derData];
    }
}

// Check if valid certificate exists
- (BOOL)isValidCertificate
{
    CFDataRef keyChainIDRef = CFDataCreate(NULL, keyChainID, keyChainIDLength);
    
    NSDictionary *dictionary = @{(__bridge id)kSecClass:(__bridge id)kSecClassKey,
                                 (__bridge id)kSecAttrApplicationTag:(__bridge id)keyChainIDRef,
                                 (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeRSA,
                                 (__bridge id)kSecReturnData:(__bridge id)kCFBooleanTrue};
    
    CFDataRef certData;
    OSStatus secError = SecItemCopyMatching((__bridge CFDictionaryRef)dictionary,
                                            (CFTypeRef *)&certData);
    
    CFRelease(keyChainIDRef);
    
    if (errSecSuccess != secError)
        return NO;
    
    if (nil == certData)
        return NO;
    
    return YES;
}

// Return encrypted string as NSData
- (NSData *)encryptData:(NSString *)data
{
    SecKeyRef publicKeyRef = [self publicKeyFromKeyChain];
    
    if (nil == publicKeyRef)
        return nil;
    
    size_t blockSize = SecKeyGetBlockSize(publicKeyRef);
    
    uint8_t *plainBuffer = calloc(blockSize, sizeof(uint8_t));
    
    strcpy((char *)plainBuffer, [data UTF8String]);
    
    uint8_t *cipherBuffer = calloc(blockSize, sizeof(uint8_t));
    
    size_t cipherBufferLength = blockSize;
    
    NSData *encryptedData = nil;
    
    OSStatus secError = SecKeyEncrypt(publicKeyRef, kSecPaddingPKCS1,
                                      plainBuffer, strlen((char *)plainBuffer),
                                      cipherBuffer, &cipherBufferLength);
    
    if (errSecSuccess == secError)
    {
        encryptedData = [[NSData alloc] initWithBytes:cipherBuffer
                                               length:cipherBufferLength];
        //NSLog(@"Encrypted data: %@", encryptedData);
    }
    
    free(cipherBuffer);
    free(plainBuffer);
    
    return encryptedData;
}

// Return encrypted string as NSString
- (NSString *)encryptString:(NSString *)data
{
    NSData *encryptedData = [self encryptData:data];
    
    size_t blockSize = [encryptedData length];
    
    // Double sized buffer to store ASCII symbols (1 hex byte is 2 ASCII bytes, 0x16 -> "16", 0xA8 -> "A8")
    // plus one zero byte
    char *asciiBuffer = calloc((blockSize << 1) + 1, sizeof(char));
    
    [self hexToAsc:(uint8_t *)[encryptedData bytes]
            length:[encryptedData length]
      outputBuffer:asciiBuffer];
    
    NSString *asciiEncryptedData = [[NSString alloc] initWithUTF8String:asciiBuffer];
    //NSLog(@"Encrypted ASCII data:%@", asciiEncryptedData):
    
    free(asciiBuffer);
    
    return asciiEncryptedData;
}

- (BOOL)deletePublicKeyFromKeyChain
{
    CFDataRef keyChainIDRef = CFDataCreate(NULL, keyChainID, keyChainIDLength);
    
    NSDictionary *dictionary = @{(__bridge id)kSecClass:(__bridge id)kSecClassKey,
                                 (__bridge id)kSecAttrApplicationTag:(__bridge id)keyChainIDRef,
                                 (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeRSA};
    
    CFRelease(keyChainIDRef);
    
    OSStatus secError = SecItemDelete((__bridge CFDictionaryRef)dictionary);
    
    return (errSecSuccess == secError || errSecItemNotFound == secError);
}

// Store public key extracted from certificate
- (BOOL)setPublicKeyFromCertificate:(NSData *)certData
{
    if (0 == certData.length)
        return NO;
    
    SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
    
    if (nil == certRef)
        return NO;
    
    CFDataRef certDataRef = SecCertificateCopyData(certRef);
    
    if (nil == certDataRef)
        return NO;
    
    CFDataRef keyChainIDRef = CFDataCreate(NULL, keyChainID, keyChainIDLength);
    
    NSDictionary *dictionary = @{(__bridge id)kSecClass:(__bridge id)kSecClassKey,
                                 (__bridge id)kSecAttrApplicationTag:(__bridge id)keyChainIDRef,
                                 (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeRSA,
                                 (__bridge id)kSecValueData:(__bridge id)certDataRef};
    
    CFRelease(certDataRef);
    CFRelease(keyChainIDRef);
    
    CFTypeRef result;
    OSStatus secError = SecItemAdd((__bridge CFDictionaryRef)dictionary, &result);
    
    return (errSecSuccess == secError && nil != result);
}

// Extract public key from KeyChain
- (SecKeyRef)publicKeyFromKeyChain
{
    CFDataRef keyChainIDRef = CFDataCreate(NULL, keyChainID, keyChainIDLength);
    
    NSDictionary *dictionary = @{(__bridge id)kSecClass:(__bridge id)kSecClassKey,
                                 (__bridge id)kSecAttrApplicationTag:(__bridge id)keyChainIDRef,
                                 (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeRSA,
                                 (__bridge id)kSecReturnData:(__bridge id)kCFBooleanTrue};
    
    CFDataRef certData;
    OSStatus secError = SecItemCopyMatching((__bridge CFDictionaryRef)dictionary,
                                            (CFTypeRef *)&certData);
    
    CFRelease(keyChainIDRef);
    
    if (errSecSuccess != secError)
        return nil;
    
    if (nil == certData)
        return nil;
    
    SecCertificateRef certRef = SecCertificateCreateWithData(NULL, certData);
    
    if (nil == certRef)
        return nil;
    
    return [self secKeyFromCertificate:certRef];
}

// Extract public key from certificate
- (SecKeyRef)secKeyFromCertificate:(SecCertificateRef)certRef
{
    CFArrayRef cfArray = CFArrayCreate(NULL, (const void **)&certRef, 1, &kCFTypeArrayCallBacks);
    
    SecPolicyRef secPolicyRef = SecPolicyCreateBasicX509();
    
    SecTrustRef secTrustRef;
    SecTrustCreateWithCertificates(cfArray, secPolicyRef, &secTrustRef);
    
    CFRelease(cfArray);
    
    SecTrustResultType secTrustResult;
    OSStatus secError = SecTrustEvaluate(secTrustRef, &secTrustResult);
    
    if (errSecSuccess != secError || nil == secTrustRef)
        return nil;
    
    return SecTrustCopyPublicKey(secTrustRef);
}

// Convert sequence of hex bytes with given length into sequence of ASCII symbols
// The length of ASCII buffer should be 2 * (length of hex buffer)
- (void)hexToAsc:(uint8_t *)inputData
          length:(NSUInteger)length
    outputBuffer:(char *)outputData
{
    for (int i = 0, j = 0; i < length; ++i)
    {
        outputData[j++] = hex2Asc(inputData[i] >> 4);
        outputData[j++] = hex2Asc(inputData[i] & 0x0F);
    }
}

// Convert hex byte into ASCII
uint8_t hex2Asc(uint8_t n)
{
    return (n < 10) ? n + '0' : (n - 10) + 'A';
}

@end
