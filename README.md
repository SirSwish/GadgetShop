                                                            _                                                                                               
                                         ^^                /|\                                                                                              
                   _____________________|  |_____         /||o\                                                                                             
                  /________G A D G E T __________\       /|o|||\                                                                                            
                 /___________S H O P _____________\     /|||||o|\                                                                                           
                   ||___|___||||||||||||___|__|||      /||o||||||\                                                                                          
                   ||___|___||||||||||||___|__|||          | |                                                                                              
                   ||||||||||||||||||||||||||||||oooooooooo| |ooooooo                                                                                       
    ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo

# Gadget Shop
GadgetShop is a Python CLI that imports RP++ gadget dumps and helps you assemble ROP chains to set up and call VirtualAlloc for DEP bypass. It can:

- **Filter by bad‐byte addresses**:  
  Accepts a list of bad‐byte patterns and removes any gadget whose address contains disallowed bytes (e.g., `\x00`, `\x0a`).

- **Exclude problematic opcodes**:  
  • Filters out gadgets containing `call` or `jmp` instructions (so you don’t accidentally divert control flow).  
  • Filters out any gadget with a `leave` instruction (since `leave` clobbers ESP).  
  • Removes single‐instruction `ret`/`retn` gadgets, which are rarely helpful beyond very specific circumstances.

- **Search across buckets**:  
  Organizes imported RP++ gadgets into categories (or “buckets”) by instruction type (e.g., all `pop reg; ret`, all `mov reg, reg; ret`, etc.). You can quickly query “show me every `xor eax, eax` gadget” or “all `push`‐related gadgets” across every bucket.

- **Register‐to‐register move‐path demonstration**:  
  Given two registers (e.g., EAX → EDX), it finds a chain of move‐style gadgets (e.g., `mov edx, eax; ret` or `xor edx, edx; add edx, eax; ret`) that transfer the desired value without clobbering any other critical register. If a gadget in the path would overwrite a needed register, GadgetShop skips it, ensuring the chain you see actually preserves all other registers you rely on.

- **Partial ROP‐chain automation**:  
  Once you’ve identified which registers need which values (for example, setting up `EAX = lpAddress`, `ECX = dwSize`, etc.), GadgetShop can automatically stitch together the necessary gadget addresses into a “skeleton” chain. It will even insert a placeholder for the `call [VirtualAlloc]` sequence (so you can replace it later with the actual Import Address Table (IAT) entry once you know its address).

- **Interactive GUI presentation**:  
  All imported gadgets appear in a sortable/filterable table (showing address, mnemonic, and affected registers). Any move‐path or VirtualAlloc chain can be expanded in a tree view, letting you click through each gadget and see its disassembly bytes in a side pane.

- **Chain export**:  
  Once you confirm a partial or complete chain, GadgetShop exports the raw addresses as a hex list or a Python array, ready for direct inclusion in your exploit script or shellcode builder.

**TODO (in‐progress):** Continue expanding the “autorop” functionality so that GadgetShop can automatically align ESP to point directly at the VirtualAlloc call, replace the skeleton call stub with real IAT addresses/values, and fully generate a working ROP chain without manual stitching.
