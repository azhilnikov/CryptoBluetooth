//
//  Cryptor.h
//  CryptoBluetooth
//
//  Created by Alexey on 5/06/2016.
//  Copyright © 2016 Alexey Zhilnikov. All rights reserved.
//

#ifndef Cryptor_h
#define Cryptor_h

#import <Foundation/Foundation.h>

@interface Cryptor : NSObject

+ (Cryptor *)sharedStore;
- (void)setCertificate:(NSData *)derData;
- (BOOL)isValidCertificate;
- (BOOL)deletePublicKeyFromKeyChain;
- (NSData *)encryptData:(NSString *)data;
- (NSString *)encryptString:(NSString *)data;
- (NSData *)cryptData:(NSData *)data withOperation:(BOOL)encryption;

@end

#endif /* Cryptor_h */
