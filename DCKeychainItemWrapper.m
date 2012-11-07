//
//  DCKeychainItemWrapper.m
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

#import "DCKeychainItemWrapper.h"
#import <Security/Security.h>

/*
 
 These are the default constants and their respective types,
 available for the kSecClassGenericPassword Keychain Item class:
 
 kSecAttrAccessGroup			-		CFStringRef
 kSecAttrCreationDate		-		CFDateRef
 kSecAttrModificationDate    -		CFDateRef
 kSecAttrDescription			-		CFStringRef
 kSecAttrComment				-		CFStringRef
 kSecAttrCreator				-		CFNumberRef
 kSecAttrType                -		CFNumberRef
 kSecAttrLabel				-		CFStringRef
 kSecAttrIsInvisible			-		CFBooleanRef
 kSecAttrIsNegative			-		CFBooleanRef
 kSecAttrAccount				-		CFStringRef
 kSecAttrService				-		CFStringRef
 kSecAttrGeneric				-		CFDataRef
 
 See the header file Security/SecItem.h for more details.
 
 */

@interface DCKeychainItemWrapper ()

@property (nonatomic, strong) NSMutableDictionary *data;
@property (unsafe_unretained, readonly) NSNumberFormatter *numberFormatter;
@property (unsafe_unretained, readonly) NSDateFormatter *dateFormatter;
@property (nonatomic, strong) NSMutableDictionary *keychainItemData;
@property (unsafe_unretained, readonly) NSMutableDictionary *genericPasswordQuery;

- (void)storeData;
- (void)readData;
/*
 The decision behind the following two methods (secItemFormatToDictionary and dictionaryToSecItemFormat) was
 to encapsulate the transition between what the detail view controller was expecting (NSString *) and what the
 Keychain API expects as a validly constructed container class.
 */
- (NSMutableDictionary *)secItemFormatToDictionary:(NSDictionary *)dictionaryToConvert;
- (NSMutableDictionary *)dictionaryToSecItemFormat:(NSDictionary *)dictionaryToConvert;
- (id)initWithIdentifier: (NSString *)identifier accessGroup:(NSString *) accessGroup;

// Updates the item in the keychain, or adds it if it doesn't exist.
- (void)writeToKeychain;

@end

@implementation DCKeychainItemWrapper

@synthesize data = data_;
@synthesize keychainItemData = keychainItemData_;

static NSString *keychainIdentifier = @"Keychain";

+ (DCKeychainItemWrapper *)sharedWrapper {
	static dispatch_once_t pred;
	static KeychainItemWrapper *_sharedWrapper = nil;
	
	dispatch_once(&pred, ^
				  {
					  _sharedWrapper = [[self alloc] initWithIdentifier:keychainIdentifier accessGroup:nil];
				  });
	
	return _sharedWrapper;
}


#pragma mark - Properties

- (NSDateFormatter *)dateFormatter {
	if (dateFormatter_ != nil) {
		return dateFormatter_;
	}
	
	dateFormatter_ = [[NSDateFormatter alloc] init];
	[dateFormatter_ setDateStyle:NSDateFormatterFullStyle];
	[dateFormatter_ setTimeStyle:NSDateFormatterFullStyle];
	
	return dateFormatter_;
}

- (NSNumberFormatter *)numberFormatter {
	if (numberFormatter_ != nil) {
		return numberFormatter_;
	}
	
	numberFormatter_ = [[NSNumberFormatter alloc] init];
	
	return numberFormatter_;
}

- (NSMutableDictionary *)genericPasswordQuery {
	if (genericPasswordQuery_ != nil) {
		return genericPasswordQuery_;
	}
	
	genericPasswordQuery_ = [[NSMutableDictionary alloc] init];
	
	return genericPasswordQuery_;
}


#pragma mark - Initialization

- (id)initWithIdentifier:(NSString *)identifier accessGroup:(NSString *)accessGroup {
    self = [super init];
	
	if (self) {
		self.data = [[NSMutableDictionary alloc] init];
		
        // Begin Keychain search setup. The genericPasswordQuery leverages the special user
        // defined attribute kSecAttrGeneric to distinguish itself between other generic Keychain
        // items which may be included by the same application.
		[self.genericPasswordQuery setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
		
		[self.genericPasswordQuery setObject:identifier forKey:(__bridge id)kSecAttrGeneric];
        [self.genericPasswordQuery setObject:identifier forKey:(__bridge id)kSecAttrAccount];
		[self.genericPasswordQuery setObject:[[NSBundle mainBundle] bundleIdentifier] forKey:(__bridge id)kSecAttrService];
		
		// The keychain access group attribute determines if this item can be shared
		// amongst multiple apps whose code signing entitlements contain the same keychain access group.
		if (accessGroup != nil) {
#if TARGET_IPHONE_SIMULATOR
			// Ignore the access group if running on the iPhone simulator.
			//
			// Apps that are built for the simulator aren't signed, so there's no keychain access group
			// for the simulator to check. This means that all apps can see all keychain items when run
			// on the simulator.
			//
			// If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
			// simulator will return -25243 (errSecNoAccessForItem).
#else
			
			[self.genericPasswordQuery setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
#endif
		}
		
		// Use the proper search constants, return only the attributes of the first match.
        [self.genericPasswordQuery setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
        [self.genericPasswordQuery setObject:(id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
        
        NSDictionary *tempQuery = [NSDictionary dictionaryWithDictionary:self.genericPasswordQuery];
        
        CFTypeRef localResult;
        if (SecItemCopyMatching((__bridge CFDictionaryRef)tempQuery, &localResult) == noErr) {
			NSDictionary *result = objc_retainedObject(localResult);
			
			// load the saved data from Keychain.
            self.keychainItemData = [self secItemFormatToDictionary:result];
			
			[self readData];
		} else {
            // Stick these default values into keychain item if nothing found.
            OSStatus junk = noErr;
			if (!self.keychainItemData) {
				self.keychainItemData = [[NSMutableDictionary alloc] init];
			} else {
				NSMutableDictionary *tempDictionary = [self dictionaryToSecItemFormat:self.keychainItemData];
				junk = SecItemDelete((__bridge CFDictionaryRef)tempDictionary);
				NSAssert( junk == noErr || junk == errSecItemNotFound, @"Problem deleting current dictionary." );
			}
			
			// Default attributes for keychain item.
			[self.keychainItemData setObject:identifier forKey:(__bridge id)kSecAttrGeneric];
			[self.keychainItemData setObject:identifier forKey:(__bridge id)kSecAttrAccount];
			[self.keychainItemData setObject:[[NSBundle mainBundle] bundleIdentifier] forKey:(__bridge id)kSecAttrService];
			
			[self.keychainItemData setObject:@"" forKey:(__bridge id)kSecAttrLabel];
			[self.keychainItemData setObject:@"" forKey:(__bridge id)kSecAttrDescription];
			
			// Default data for keychain item.
			[self.keychainItemData setObject:@"" forKey:(__bridge id)kSecValueData];
			
			if (accessGroup != nil) {
#if TARGET_IPHONE_SIMULATOR
				// Ignore the access group if running on the iPhone simulator.
				//
				// Apps that are built for the simulator aren't signed, so there's no keychain access group
				// for the simulator to check. This means that all apps can see all keychain items when run
				// on the simulator.
				//
				// If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
				// simulator will return -25243 (errSecNoAccessForItem).
#else
				[self.keychainItemData setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
#endif
			}
		}
    }
    
	return self;
}

- (void)setBool:(BOOL)inBool forKey:(id)key {
	NSNumber *inNumber = [NSNumber numberWithBool:inBool];
	NSString *inString = [self.numberFormatter stringFromNumber:inNumber];
	[self setString:inString forKey:key];
}

- (BOOL)boolForKey:(id)key {
	NSString *outString = [self stringForKey:key];
	if (outString) {
		NSNumber *outNumber = [self.numberFormatter numberFromString:outString];
		return [outNumber boolValue];
	} else {
		return NO;
	}
}

- (void)setString:(NSString *)inString forKey:(id)key {
	if (inString) {
		[self.data setObject:inString forKey:key];
	} else {
		[self.data removeObjectForKey:key];
	}
	
	[self storeData];
}

- (NSString *)stringForKey:(id)key {
	return [self.data objectForKey:key];
}

- (void)setDate:(NSDate *)inDate forKey:(id)key {
	NSString *inString = [self.dateFormatter stringFromDate:inDate];
	[self setString:inString forKey:key];
}

- (void)setArray:(NSArray *)array forKey:(id)key {
	NSData *jsonData = [NSJSONSerialization dataWithJSONObject:array
													   options:0
														 error:nil];
	
	NSString *json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
	
    [self setString:json forKey:key];
}

- (NSArray *)arrayForKey:(id)key {
	NSString *json = [self stringForKey:key];
	
	NSArray *array = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding]
													 options:0
													   error:nil];
	
    return array;
}

- (void)setDictionary:(NSDictionary *)dictionary forKey:(id)key {
	NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary
													   options:0
														 error:nil];
	
	NSString *json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
	
    [self setString:json forKey:key];
}

- (NSDictionary *)dictionaryForKey:(id)key {
	NSString *json = [self stringForKey:key];
	
	NSDictionary *dictionary = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding:NSUTF8StringEncoding]
															   options:0
																 error:nil];
	
    return dictionary;
}

- (NSDate *)dateForKey:(id)key {
	NSString *outString = [self stringForKey:key];
	if (outString) {
		return [self.dateFormatter dateFromString:outString];
	} else {
		return nil;
	}
}

- (void)storeData {
	NSError *error = nil;
	NSData *jsonData = [NSJSONSerialization dataWithJSONObject:self.data
													   options:0
														 error:&error];
	if (jsonData) {
		NSString *json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
		
		[self.keychainItemData setObject:json forKey:(__bridge id)kSecValueData];
		[self writeToKeychain];
	} else {
		NSLog(@"Error Storing Keychain Data: %@", error);
	}
}

- (void)readData {
	NSError *error = nil;
	NSString *jsonString = [self.keychainItemData objectForKey:(__bridge id)kSecValueData];
	
	if (jsonString) {
		self.data = [NSJSONSerialization JSONObjectWithData:[jsonString dataUsingEncoding:NSUTF8StringEncoding]
													options:NSJSONReadingMutableContainers
													  error:&error];
		
		if (self.data == nil) {
			NSLog(@"Error Reading Keychain Data: %@", error);
			
			self.data = [[NSMutableDictionary alloc] init];
		}
	} else {
		self.data = [[NSMutableDictionary alloc] init];
	}
}

- (void)resetKeychainItem {
	OSStatus junk = noErr;
	
    if (!self.keychainItemData) {
        self.keychainItemData = [[NSMutableDictionary alloc] init];
    } else {
        NSMutableDictionary *tempDictionary = [self dictionaryToSecItemFormat:self.keychainItemData];
		junk = SecItemDelete((__bridge CFDictionaryRef)tempDictionary);
        NSAssert( junk == noErr || junk == errSecItemNotFound, @"Problem deleting current dictionary." );
    }
    
	// Default attributes for keychain item.
	[self.keychainItemData setObject:keychainIdentifier forKey:(__bridge id)kSecAttrGeneric];
	[self.keychainItemData setObject:keychainIdentifier forKey:(__bridge id)kSecAttrAccount];
	[self.keychainItemData setObject:[[NSBundle mainBundle] bundleIdentifier] forKey:(__bridge id)kSecAttrService];
	
    [self.keychainItemData setObject:@"" forKey:(__bridge id)kSecAttrLabel];
    [self.keychainItemData setObject:@"" forKey:(__bridge id)kSecAttrDescription];
    
	// Default data for keychain item.
    [self.keychainItemData setObject:@"" forKey:(__bridge id)kSecValueData];
	
	[self writeToKeychain];
	
	[self readData];
}

- (NSMutableDictionary *)dictionaryToSecItemFormat:(NSDictionary *)dictionaryToConvert {
    // The assumption is that this method will be called with a properly populated dictionary
    // containing all the right key/value pairs for a SecItem.
    
    // Create a dictionary to return populated with the attributes and data.
    NSMutableDictionary *returnDictionary = [NSMutableDictionary dictionaryWithDictionary:dictionaryToConvert];
    
    // Add the Generic Password keychain item class attribute.
    [returnDictionary setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    
    // Convert the NSString to NSData to meet the requirements for the value type kSecValueData.
	// This is where to store sensitive data that should be encrypted.
    NSString *passwordString = [dictionaryToConvert objectForKey:(__bridge id)kSecValueData];
    [returnDictionary setObject:[passwordString dataUsingEncoding:NSUTF8StringEncoding] forKey:(__bridge id)kSecValueData];
    
    return returnDictionary;
}

- (NSMutableDictionary *)secItemFormatToDictionary:(NSDictionary *)dictionaryToConvert {
    // The assumption is that this method will be called with a properly populated dictionary
    // containing all the right key/value pairs for the UI element.
    
    // Create a dictionary to return populated with the attributes and data.
    NSMutableDictionary *returnDictionary = [NSMutableDictionary dictionaryWithDictionary:dictionaryToConvert];
    
    // Add the proper search key and class attribute.
    [returnDictionary setObject:(id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    [returnDictionary setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    
	CFTypeRef localResult;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)returnDictionary, &localResult) == noErr) {
		NSData *passwordData = objc_retainedObject(localResult);
		
        // Remove the search, class, and identifier key/value, we don't need them anymore.
        [returnDictionary removeObjectForKey:(__bridge id)kSecReturnData];
        
        // Add the password to the dictionary, converting from NSData to NSString.
        NSString *password = [[NSString alloc] initWithBytes:[passwordData bytes]
													  length:[passwordData length]
													encoding:NSUTF8StringEncoding];
		
        [returnDictionary setObject:password forKey:(__bridge id)kSecValueData];
    }
    else
    {
        // Don't do anything if nothing is found.
        NSAssert(NO, @"Serious error, no matching item found in the keychain.\n");
    }
	
	return returnDictionary;
}

- (void)writeToKeychain {
	OSStatus result;
    
	CFTypeRef localResult;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)self.genericPasswordQuery, &localResult) == noErr) {
		NSDictionary *attributes = objc_retainedObject(localResult);
		
        // First we need the attributes from the Keychain.
        NSMutableDictionary *updateItem = [NSMutableDictionary dictionaryWithDictionary:attributes];
        // Second we need to add the appropriate search key/values.
        [updateItem setObject:[self.genericPasswordQuery objectForKey:(__bridge id)kSecClass] forKey:(__bridge id)kSecClass];
        
        // Lastly, we need to set up the updated attribute list being careful to remove the class.
        NSMutableDictionary *tempCheck = [self dictionaryToSecItemFormat:self.keychainItemData];
        [tempCheck removeObjectForKey:(__bridge id)kSecClass];
		
#if TARGET_IPHONE_SIMULATOR
		// Remove the access group if running on the iPhone simulator.
		//
		// Apps that are built for the simulator aren't signed, so there's no keychain access group
		// for the simulator to check. This means that all apps can see all keychain items when run
		// on the simulator.
		//
		// If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
		// simulator will return -25243 (errSecNoAccessForItem).
		//
		// The access group attribute will be included in items returned by SecItemCopyMatching,
		// which is why we need to remove it before updating the item.
		[tempCheck removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
#endif
        
        // An implicit assumption is that you can only update a single item at a time.
		
        result = SecItemUpdate((__bridge CFDictionaryRef)updateItem, (__bridge CFDictionaryRef)tempCheck);
		
		NSAssert(result == noErr, @"Couldn't update the Keychain Item." );
    } else {
        // No previous item found; add the new one.
        result = SecItemAdd((__bridge CFDictionaryRef)[self dictionaryToSecItemFormat:self.keychainItemData], NULL);
		
		NSAssert(result == noErr, @"Couldn't add the Keychain Item." );
    }
}


#pragma mark - Raw Data Methods

- (void)setKeychainData:(NSDictionary *)data {
	self.data = [NSMutableDictionary dictionaryWithDictionary:data];
	
	[self storeData];
}

- (NSDictionary *)getKeychainData {
	return [NSDictionary dictionaryWithDictionary:self.data];
}

@end