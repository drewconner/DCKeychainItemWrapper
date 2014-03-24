//
//  DCViewController.m
//  DCKeychainSampleApp
//
//  Created by Drew Conner on 3/24/14.
//  Copyright (c) 2014 Drew Conner. All rights reserved.
//

#import "DCViewController.h"
#import "DCKeychainItemWrapper.h"


#define kSampleStringKey	@"SampleStringKey"


@interface DCViewController ()

@end


@implementation DCViewController

- (IBAction)writeData:(id)sender {
	NSString *string = @"Test";
	
	[[DCKeychainItemWrapper sharedWrapper] setString:string forKey:kSampleStringKey];
	
	NSLog(@"Wrote \"%@\" to Keychain", string);
}

- (IBAction)readData:(id)sender {
	NSString *string = [[DCKeychainItemWrapper sharedWrapper] stringForKey:kSampleStringKey];
	
	NSLog(@"Read \"%@\" from Keychain", string);
}

- (IBAction)resetData:(id)sender {
	[[DCKeychainItemWrapper sharedWrapper] resetKeychainItem];
	
	NSLog(@"Reset Keychain");
}

@end
