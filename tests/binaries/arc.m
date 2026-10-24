// tests/binaries/arc.m
#import <Foundation/Foundation.h>

// Returned object forces ARC to emit objc_retainAutoreleasedReturnValue /
// objc_release in the caller; a single-function sample gets optimized away.
NSObject *make_object(void) { return [[NSObject alloc] init]; }

int main(void) {
  NSObject *o = make_object();
  NSLog(@"%@", o);
  return 0;
}
