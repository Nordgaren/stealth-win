# stealth-win  
A Windows framework for creating projects that want to hide from EDR. Includes hiding strings and obfuscating function calls in Rust. Creates and embeds a PE resource with 
XOR'd strings and AES encrypted payloads on every build. Provides position independant abstractions that work even in and 
unmapped pe file.

# How to use  
At the moment, the only way to get at the config is by editing the crate itself. It's not ideal, but I haven't figured out a 
way to get the build script to read something in the project it's been added to. My current suggestion is to clone this crate and
put it next to your project, in whatever folder you have it in, and import it like so:
```toml
[dependencies]  
stealth-win = {path="../stealth-win"}  
```

You can then edit the config and embed any strings you would like into the PE resource, or change the padding size, etc.
The build_config file is protected by a git feature that ignores changes to a file, so you can still contribute definitions,
and change the config file!

#### Environment Variables
STEALTH_NO_BUILD_SCRIPT  

You can set `STEALTH_NO_BUILD_SCRIPT` to anything and it will cancel the build script when cargo check is run. This is useful when you
have an IDE that wil run cargo check every time you save a file, as to not build a whole new PE every time you save. I only know
how to do this easily for VSCode Rust Analyzer crate.

Go to extensions -> Rust Analyzer ⚙ -> Extension Settings -> Search: `@ext:rust-lang.rust-analyzer check` ->
"Rust-analyzer > Check:Extra Env" -> Edit in settings.json and add this to the json file.
```json
"rust-analyzer.check.extraEnv": {
"STEALTH_NO_BUILD_SCRIPT" : "true"
}
```

# Contributing  
If you would like to add new definitions to the dll modules, just keep the function type and wrapper function definitions 
in alphabetical order. I will work on making the struct definitions also alphabetical order.  

If you have features you'd like to add, just make sure to follow the goals at the bottom of the page. Mainly the implementation
of features that work in both a mapped and unmapped (like a reflective loader dll) state.

The build config is protected by `git update-index --skipworktree`, so your changes won't show up to that file!  If you
need to add something to the config while contributing, you can use
`git update-index --no-skipworktree ./build_src/build_config.rs` to remove this flag. Just make sure to put it back when
you are done updating the config file!

# Features  
### PE Reader  
This is a class that will allow you to read a PE, regardless of if it is 32 bit or 64 bit. It is abstracted away with the use of
if statements and TypeState abstraction. In it's current implementation, there is a possibility the compiler eventually uses
memcpy (This was an issue with my first implementation, too). memcpy will cause this to not work in an unmapped PE, which is 
bad, because the crate Win API functions use it to get the resource from the consuming executable.  

### Resource File  
Resource file built with the build script every time build is ran. Randomizes the position of strings and payload, as well as
padding between entries. This resource is put into your final EXE and can be indexed using `util::get_resource_bytes` with
a `resource_id`, `positon`, and `length`.  

### Embedded Strings  
Strings can be added to the binary in xor'd format with their own key, from the `build_config.rs`  
You can use the built in `crypto_util::get_xor_encrypted_bytes` which returns an SVec<u8>, which contains the bytes of your string  
(with no null terminator). You can push a `0` onto this svec, if you need to pass the string to a function that expects  
a null terminated string. There are also `util::compare_xor_str_and_str_bytes` and `util::compare_xor_str_and_w_str_bytes` function 
which are there to aid in comparing the xor'd strings with non xor'd strings. You can get a slice from any pointer to a 
C string and the `util::strlen` function, which you can pass in to compare with these two functions, as well as the key 
to the xor string. This will not decrypt the string, but rather xor encrypt the target string in place, byte by byte, and 
compare to the xor'd string in the embedded PE resource. The const values to retrieve your strings from the PE resource have  
the following values replaced by an underscore: `" " "," "." "\0"`. These 
can be added to in the `build_src::build_util::make_const_name` function.

### SVec  
A vector type, mainly based on Vec\<T\> code that can be used in an unmapped PE, by utilizing the internal `GetModuleHandle` 
and `GetProcAddress` to call `VirtualAlloc` and `VirtualFree` to manage a buffer of whatever type you give it.  This does not
require that the PE you are running your code from is mapped into memory properly. It just matters that `kernel32` and
`ntdll` are mapped into memory in the process the code (unmapped dll) is running in, which it should be.  

### Win API  
Windows API calls and structures, and wrappers to get and call these functions through internal `GetModuleHandleX` and 
`GetProcAddresX`, both of which use the internal xor string comparison algorithm to find the function call.  

### Config  
Add strings for your own `GetModuleHandleX`and `GetProcAddresX` searches, target file for shellcode or a DLL payload which is
AES encrypted and stored in the embedded PE Resource with the strings. Can change the resource ID, resource file name or the 
range of randomly generated bytes between resource entries. More to come in the config. I would eventually like to figure out a 
way for the user to keep a config file in their project. As it stand, now. you need to edit the crate, itself.  

# Goals  
### Keep as much of this position independent  
I would like most of this code to be usable in an unmapped state, i.e, if you are trying to use this library in a reflective
loader. This may end up driving the project to be a `#[no_std]` crate, in the end.  
### Add more mechanisms for avoiding detection for various activities    
This is just the start. The project started because I needed a way to hide my strings, but I didn't want 
to manually encrypt and pack strings into my project.  
### Learn more about Windows internals   
and maybe Linux internals, down the line, too!  
### Encourage more Rust RE tooling   
Better static analysis would be good! Soon I want to test if I can get away with doing a lot more in front of Windows Defender
purely based on the static analysis for rust binaries not being as good.  

# TODO
* make a todo list...
