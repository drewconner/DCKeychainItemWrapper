//
//  DCKeychainItemWrapper.h
//  DCKeychainItemWrapper
//
//  Copyright (c) 2012 Drew Conner. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//

#import <UIKit/UIKit.h>

/*
 The KeychainItemWrapper class is an abstraction layer for the iPhone Keychain communication. It is merely a
 simple wrapper to provide a distinct barrier between all the idiosyncracies involved with the Keychain
 CF/NS container objects.
 
 This wrapper is based on Apple's sample code, with methods added for easier use.
 */
@interface DCKeychainItemWrapper : NSObject

+ (DCKeychainItemWrapper *)sharedWrapper;

// Methods for key/values
- (void)setBool:(BOOL)inBool forKey:(id)key;
- (BOOL)boolForKey:(id)key;
- (void)setString:(NSString *)inString forKey:(id)key;
- (NSString *)stringForKey:(id)key;

- (void)setArray:(NSArray *)array forKey:(id)key;
- (NSArray*)arrayForKey:(id)key;

- (void)setDictionary:(NSDictionary *)dictionary forKey:(id)key;
- (NSDictionary*)dictionaryForKey:(id)key;

- (void)setDate:(NSDate *)inDate forKey:(id)key;
- (NSDate *)dateForKey:(id)key;

// Methods for accessing raw data
- (void)setKeychainData:(NSDictionary *)data;
- (NSDictionary *)getKeychainData;

// Initializes and resets the default generic keychain item data.
- (void)resetKeychainItem;

@end