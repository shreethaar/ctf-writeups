# Trippi Troppa Chaos

- Category: reverse
- Difficulty: medium 
- Author: ha1fdan

The baker got infected with Italian brainrot and obfuscated our flag encoder with memes and nested functions. Can you help us find our flag?

### Solution: 

1. View trippa_troppa_sus.py with a text editor 

```py
#!/usr/bin/env python3
import sys as _tralalero_tralala_impostor_____
(lambda _bombardiro_crocodilo___: [
    setattr(__builtins__, '__boneca_ambalabu_toilet____', __import__('base64').b85encode),
    setattr(__builtins__, '___trippa_troppa_mewing___', __import__('hashlib').sha256),
    setattr(__builtins__, '__tung_tung_sahur_cycle_____', __import__('itertools').cycle),
    setattr(__builtins__, '____pinguino_arrabiato_seed____', __import__('random').seed)
][_bombardiro_crocodilo___] and None)(0) or ____pinguino_arrabiato_seed____(69420)

def ___ranocchio_turbina_function_factory____():
    def ____lirilì_rilà_final_boss_____():
        def _____trippi_troppa_skibidi_____():
            def ______crocodina_gigachad_nested______():
                def _______tralala_alpha_transformation_______():
                    def ________boneca_beta_elimination________():
                        def _________sahur_sigma_activities_________():
                            def __________bombardiro_mewing__________():
                                def ___________trippa_no_cap___________():
                                    def ____________tung_bussin_respectfully____________():
                                        def _____________tralalero_slay_queen_energy_____________():
                                            __fanum_tax_pinguino____ = lambda ___cringe_normie_bombardiro___, ____based_chad_crocodilo____: (lambda ____uwu_owo_tralalero____: [__c__ for __c__ in ____uwu_owo_tralalero____])(
                                                [___x___ ^ ___y___ for ___x___, ___y___ in zip(___cringe_normie_bombardiro___, __tung_tung_sahur_cycle_____(____based_chad_crocodilo____))]
                                            )
                                            
                                            def ____boneca_ambalabu_university____(___x_trippa___, ___y_troppa___):
                                                return (lambda ____bruh_moment_lirilì____: ____bruh_moment_lirilì____.digest()[:len(___y_troppa___)])(
                                                    ___trippa_troppa_mewing___(
                                                        ((___x_trippa___.decode() if isinstance(___x_trippa___, bytes) else ___x_trippa___) + 
                                                         (___y_troppa___.decode() if isinstance(___y_troppa___, bytes) else ___y_troppa___)).encode()
                                                    )
                                                )
                                            
                                            def ____tralalero_griddy_dance____(___x_ranocchio___):
                                                return (lambda ____fortnite_bombardiro_pass____: 
                                                       [___c_crocodina___ for ___c_crocodina___ in ____fortnite_bombardiro_pass____]
                                                )([((___c_sahur___ * 7) % 256) for ___c_sahur___ in ___x_ranocchio___])
                                            
                                            def ____tung_reverse_uno_card____(___x_pinguino___):
                                                return (lambda ____amogus_sus_trippi____: ____amogus_sus_trippi____[::-1])(___x_pinguino___)
                                            
                                            def ____dead_meme_boneca_graveyard____():
                                                ____poggers_tralala____, ____chungus_rilà____, ____keanu_troppa____ = 1337, 420, 9000
                                                for ___i_bombardiro___ in (lambda ___x_crocodilo___: range(___x_crocodilo___))(5):
                                                    ____poggers_tralala____ = (____poggers_tralala____ * ____chungus_rilà____ + ____keanu_troppa____) % (___i_bombardiro___ + 7)
                                                return ____poggers_tralala____
                                            
                                            def ____touch_grass_tralalero_function____():
                                                try:
                                                    with open("flag.txt", "rb") as ____yeet_file_ambalabu____:
                                                        ____cringe_flag_pinguino____ = ____yeet_file_ambalabu____.read()
                                                except:
                                                    return "L + ratio + skill issue + no tralalero for you"
                                                
                                                ____sussy_key_bombardiro____ = b"skibidi"
                                                
                                                ____step_one_boneca____ = ____boneca_ambalabu_university____(____sussy_key_bombardiro____, ____sussy_key_bombardiro____)
                                                ____step_two_sahur____ = bytes(__fanum_tax_pinguino____(____cringe_flag_pinguino____, ____step_one_boneca____))
                                                ____step_three_trippa____ = bytes(____tralalero_griddy_dance____(____step_two_sahur____))
                                                ____step_four_troppa____ = ____tung_reverse_uno_card____(____step_three_trippa____)
                                                ____final_boss_crocodina____ = __boneca_ambalabu_toilet____(____step_four_troppa____).decode()
                                                
                                                return ____final_boss_crocodina____
                                            
                                            return ____touch_grass_tralalero_function____
                                        return _____________tralalero_slay_queen_energy_____________
                                    return ____________tung_bussin_respectfully____________
                                return ___________trippa_no_cap___________
                            return __________bombardiro_mewing__________
                        return _________sahur_sigma_activities_________
                    return ________boneca_beta_elimination________
                return _______tralala_alpha_transformation_______
            return ______crocodina_gigachad_nested______
        return _____trippi_troppa_skibidi_____
    return ____lirilì_rilà_final_boss_____

if __name__ == "__main__":
    print((lambda ___x_tralalero___: ___x_tralalero___()()()()()()()()()()()())(___ranocchio_turbina_function_factory____))
```

Looking at this obfuscated python code with ridiculous variable names and nested functions, the core loigc is still straightforward. 

Key Functions of the script:
- XOR functions with cycling key -> `__fanum_tax_pinguino____`
- Creates SHA256 hash of concatenated inputs, truncated to key lenght -> `____boneca_ambalabu_university____`
- Multiple each byte by 7 modulo 256 -> `____tralalero_griddy_dance____`
- Reverse the byte array -> `____tung_reverse_uno_card____` 
- Base85 encoding -> `__boneca_ambalabu_toilet____`

So here is the encryption process:
- Read flag from "flag.txt"
- Create key by hashing "skibidi" + "skibidi" (SHA256, truncated to 6 bytes)
- XOR flag with cycling key
- Multiply each byte by 7 mod 256
- Reverse the result
- Base85 encode and return

2. Generate reverse script:
To decrypt, we reverse each step: 
- Base85 decode the input 
- Reverse the byte array 
- Inverse transform, multiply by modular inverse of 7 (which is 183) mod 256 
- XOR with the same repeating key 
- Decodes as UTF-8 get the flag 

Here is the script: 

```py 
#!/usr/bin/env python3
import base64
import hashlib
import itertools

def reverse_engineer_encryption():
    # The encrypted output from the challenge
    encrypted_b85 = "qjuA_QZVI_ua24NQ}fM1hX4ecdyVShKb2vJjeQJ@Jz=zws0^9Enr1fR+Em_5w2j=p4)2<#m3EZ?m3Oo@"
    
    print(f"Encrypted (base85): {encrypted_b85}")
    
    # Step 1: Decode from base85
    try:
        step_four_data = base64.b85decode(encrypted_b85)
        print(f"After base85 decode: {step_four_data}")
    except Exception as e:
        print(f"Base85 decode error: {e}")
        return
    
    # Step 2: Reverse the "reverse uno card" operation (it's just reversing)
    step_three_data = step_four_data[::-1]
    print(f"After reverse: {step_three_data}")
    
    # Step 3: Reverse the "griddy dance" operation (multiply by 7 mod 256)
    # To reverse: we need to find the modular inverse of 7 mod 256
    # Since gcd(7, 256) = 1, the inverse exists
    # 7 * 183 = 1281 ≡ 1 (mod 256), so inverse of 7 is 183
    step_two_data = bytes([(c * 183) % 256 for c in step_three_data])
    print(f"After reversing griddy dance: {step_two_data}")
    
    # Step 4: Generate the XOR key (same as original)
    key = b"skibidi"
    # The key derivation: sha256(key + key).digest()[:len(key)]
    combined_key = key + key  # b"skibidiskibidi"
    hash_obj = hashlib.sha256(combined_key)
    xor_key = hash_obj.digest()[:len(key)]  # Take first 6 bytes
    print(f"XOR key: {xor_key}")
    
    # Step 5: Reverse the XOR operation using itertools.cycle
    key_cycle = itertools.cycle(xor_key)
    original_flag = bytes([b ^ k for b, k in zip(step_two_data, key_cycle)])
    
    print(f"Decrypted flag: {original_flag}")
    
    # Try to decode as text
    try:
        flag_text = original_flag.decode('utf-8')
        print(f"Flag as text: {flag_text}")
    except:
        print("Could not decode as UTF-8")
        # Print as hex for debugging
        print(f"Flag as hex: {original_flag.hex()}")

def test_encryption_process():
    """Test our understanding by implementing the forward process"""
    print("\n--- Testing Forward Encryption Process ---")
    
    # Test with a known flag
    test_flag = b"flag{test_flag_here}"
    print(f"Test input: {test_flag}")
    
    # Step 1: Key derivation
    key = b"skibidi"
    combined_key = key + key
    hash_obj = hashlib.sha256(combined_key)
    xor_key = hash_obj.digest()[:len(key)]
    
    # Step 2: XOR with cycling key
    key_cycle = itertools.cycle(xor_key)
    step_two = bytes([b ^ k for b, k in zip(test_flag, key_cycle)])
    
    # Step 3: Griddy dance (multiply by 7 mod 256)
    step_three = bytes([(c * 7) % 256 for c in step_two])
    
    # Step 4: Reverse
    step_four = step_three[::-1]
    
    # Step 5: Base85 encode
    result = base64.b85encode(step_four).decode()
    
    print(f"Encrypted result: {result}")
    
    # Now decrypt it back
    print("Decrypting back...")
    decrypted = base64.b85decode(result)
    decrypted = decrypted[::-1]
    decrypted = bytes([(c * 183) % 256 for c in decrypted])  # 183 is inverse of 7 mod 256
    key_cycle = itertools.cycle(xor_key)
    final = bytes([b ^ k for b, k in zip(decrypted, key_cycle)])
    print(f"Decrypted back to: {final}")

if __name__ == "__main__":
    print("=== Reversing Python CTF Challenge ===")
    reverse_engineer_encryption()
    test_encryption_process()
```

**Flag:** `brunner{tr4l4l3r0_b0mb4rd1r0_r3v3rs3_3ng1n33r1ng_sk1b1d1_m4st3r}`
