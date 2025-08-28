# Bakeware 

- Category: reverse
- Difficulty: medium-hard
- Author: Quack 

Grandma had her secret family recipe stolen! All she has left now is a weird and rusty file. Please figure out what happened to the recipe, so we can get back to baking!

### Solution:

1. Run diec on the binary 

```
$ diec rev_bakeware/Bakeware 
ELF64
    Compiler: Rust
    Compiler: GCC(3.X)
    Library: GLIBC(2.34)[DYN AMD64-64]
```
The binary is compile with Rust however the main caveat of reversing a rust binary is that its heavy use of inling,monomorphiszation and complex abstractions which produces bloated and compiler-optimized machine code that slightly obscures the original program logic. 

2. Disassemble the binary

At the address 00408c60, there is main function of `Bakeware::main`. 

```c 
00408c60    int64_t Bakeware::main::h837f6b7d44b9b487()

00408c60    {
00408c60        uint64_t var_7d8 = 0x1b600000000;
00408c83        int32_t var_7d0 = 0;
00408c8e        int16_t var_7cc = 0;
00408c98        (uint8_t)var_7d0 = 1;
00408cbc        int32_t var_408;
00408cbc        std::fs::OpenOptions::_open::hce0f5e8979d4b5a1(&var_408, &var_7d8, 
00408cbc            "Grandmas_Secret_Baking_Family_Recipe.txtFile not found. Nothing to steal :(\n"
00408cbc        "502ff05a7b51b76e740b19cc4957ad118897a25becbb87fcb662a14b2e56a5d9Secret recipe not "
00408cbc        "found. Nothing to steal :(\nGrandmas_Secret_Baking_Family_Recipe", 
00408cbc            0x28);
00408cbc        
00408cca        if (var_408 == 1)
00408cca        {
0040987a            var_7d8 = &data_45fc18;
00409882            var_7d0 = 1;
0040988e            int64_t var_7c8_7 = 8;
0040989d            int128_t var_7c0_3 = {0};
004098ad            std::io::stdio::_print::h2bb3f89bb77308e4(&var_7d8);
004098b5            std::process::exit::hc9c70ab8de590b08(0);
004098b5            /* no return */
00408cca        }
00408cca        
00408cd7        int32_t fd_1;
00408cd7        int32_t fd = fd_1;
00408cdb        var_408 = 0;
00408ce7        char* var_400 = 1;
00408cf3        uint64_t var_3f8 = 0;
00408d0c        char rax_1;
00408d0c        uint64_t rdx;
00408d0c        rax_1 =
00408d0c            _$LT$std..fs..File$u20$a...T$::read_to_string::h4d12b8c695679e1f(&fd, &var_408);
00408d0c        
00408d14        if (rax_1 & 1)
00408d14        {
004098c0            var_7d8 = rdx;
004098ea            core::result::unwrap_failed::h1b5ed8541c7bebd6(
004098ea                "called `Result::unwrap()` on an `Err` value/home/quack/."
004098ea            "rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/slice."
004098ea            "rsPadErrorextern "Oh! A Good Old Hello World Binary That Is Totally Innocent "
004098ea            "And Does Not St", 
004098ea                0x2b, &var_7d8);
004098ea            /* no return */
00408d14        }
00408d14        
00408d2a        _$LT$$RF$alloc..string.....Digest$GT$::digest::hac6b4adf5efc5232(&var_7d8, 
00408d2a            &var_408);
00408d30        int64_t rax_2 = var_408;
00408d55        uint64_t rax_4 = var_7d8;
00408d62        int64_t r14 = var_7d0;
00408d76        close(fd);
00408d80        int64_t var_968 = r14;
00408d84        int64_t var_7c8;
00408d84        
00408d84        if (var_7c8 == 0x40 && !bcmp(r14, 
00408d84            "502ff05a7b51b76e740b19cc4957ad118897a25becbb87fcb662a14b2e56a5d9Secret recipe not "
00408d84        "found. Nothing to steal :(\nGrandmas_Secret_Baking_Family_Recipe", 
00408d84            0x40))
00408d84        {
00408db6            uint64_t var_820;
00408db6            Bakeware::get_key_part::hd4d7de7168456fd6(&var_820);
00408dcd            uint64_t var_808;
00408dcd            Bakeware::get_key_part::hd4d7de7168456fd6(&var_808);
00408de4            uint64_t var_7f0;
00408de4            Bakeware::get_key_part::hd4d7de7168456fd6(&var_7f0);
00408dfb            int64_t var_8d8;
00408dfb            Bakeware::get_key_part::hd4d7de7168456fd6(&var_8d8);
00408e12            uint64_t var_878;
00408e12            Bakeware::get_key_part::hd4d7de7168456fd6(&var_878);
00408e29            uint64_t var_860;
00408e29            Bakeware::get_key_part::hd4d7de7168456fd6(&var_860);
00408e3d            int32_t* var_918;
00408e3d            Bakeware::get_key_part::hd4d7de7168456fd6(&var_918);
00408e51            Bakeware::get_key_part::hd4d7de7168456fd6(&fd);
00408e61            uint64_t var_810;
00408e61            int64_t r14_1;
00408e61            
00408e61            if (var_810 < 0)
004098f5                r14_1 = 0;
00408e61            else
00408e61            {
00408e6f                int64_t rax_7;
00408e6f                
00408e6f                if (!var_810)
00408e6f                {
00408e99                    rax_7 = 1;
00408ebf                label_408ebf:
00408ebf                    int64_t var_818;
00408ebf                    memcpy(rax_7, var_818, var_810);
00408ec5                    uint64_t rax_8 = var_808;
00408ee2                    uint64_t rax_10 = var_7f0;
00408eff                    uint64_t rax_12 = var_820;
00408f0c                    int64_t rax_13 = var_8d8;
00408f2c                    uint64_t rax_15 = var_878;
00408f49                    uint64_t rax_17 = var_860;
00408f66                    int32_t* rax_19 = var_918;
00408f85                    uint64_t var_948;
00408f85                    int64_t var_8c0_1;
00408f85                    
00408f85                    if (var_948 < 0)
00409910                        var_8c0_1 = 0;
00408f85                    else
00408f85                    {
00408fdd                        int64_t r15_1;
00408fdd                        
00408fdd                        if (!var_948)
00408fdd                        {
00409012                            r15_1 = 1;
00409021                        label_409021:
00409021                            int64_t var_950;
00409021                            memcpy(r15_1, var_950, var_948);
0040902c                            uint64_t var_6f0 = var_948;
00409034                            int128_t zmm0 = fd;
00409041                            var_7d8 = var_810;
00409051                            var_7d0 = rax_7;
00409059                            uint64_t var_7c8_1 = var_810;
00409066                            int128_t var_7c0;
00409066                            (uint64_t)var_7c0 = rax_8;
00409076                            int64_t var_800;
00409076                            *(uint64_t*)((char*)var_7c0)[8] = var_800;
0040907e                            int64_t var_7f8;
0040907e                            int64_t var_7b0 = var_7f8;
004090a3                            int64_t var_7e0;
004090a3                            int64_t var_798 = var_7e0;
004090c8                            uint64_t var_780 = var_810;
004090f8                            int64_t var_8c8;
004090f8                            int64_t var_768 = var_8c8;
00409125                            int64_t var_868;
00409125                            int64_t var_750 = var_868;
00409152                            int64_t var_850;
00409152                            int64_t var_738 = var_850;
0040917f                            int64_t var_908;
0040917f                            int64_t var_720 = var_908;
00409197                            uint64_t var_708 = var_948;
004091b4                            _$LT$$u5b$V$u5d$$u20$as$...$T$GT$$GT$::concat::hb51e64af983ca0d5(
004091b4                                &var_408, &var_7d8, 0xa);
004091b4                            
004091d0                            if (var_7d8)
004091df                                __rust_dealloc(var_7d0);
004091df                            
004091f0                            if ((uint64_t)var_7c0)
004091ff                                __rust_dealloc(*(uint64_t*)((char*)var_7c0)[8]);
004091ff                            
00409210                            int64_t var_7e8;
00409210                            
00409210                            if (rax_10)
0040921f                                __rust_dealloc(var_7e8);
0040921f                            
00409230                            if (rax_12)
0040923f                                __rust_dealloc(var_818);
0040923f                            
00409250                            int64_t var_8d0;
00409250                            
00409250                            if (rax_13)
0040925f                                __rust_dealloc(var_8d0);
00409270                            int64_t var_870;
00409270                            
00409270                            if (rax_15)
0040927f                                __rust_dealloc(var_870);
00409290                            int64_t var_858;
00409290                            
00409290                            if (rax_17)
0040929f                                __rust_dealloc(var_858);
004092b0                            int64_t var_910;
004092b0                            
004092b0                            if (rax_19)
004092bf                                __rust_dealloc(var_910);
004092bf                            
004092d0                            if (var_948)
004092df                                __rust_dealloc(r15_1);
004092df                            
004092f0                            if ((uint64_t)zmm0)
004092ff                                __rust_dealloc(*(uint64_t*)((char*)zmm0)[8]);
004092ff                            
00409305                            int64_t rbx_2 = var_408;
00409305                            
00409323                            if (var_3f8 != 0x20)
00409323                            {
004093b4                                var_7d8 = &data_45fbd8;
004093bc                                var_7d0 = 1;
004093c8                                int64_t var_7c8_2 = 8;
004093d7                                int128_t var_7c0_1 = {0};
004093ee                                core::panicking::panic_fmt::h896a0727a1a943f9(&var_7d8);
004093ee                                /* no return */
00409323                            }
00409323                            
00409335                            uint64_t var_938_1 = var_3f8 + 0x10;
0040933a                            int64_t rbx_3;
0040933a                            
0040933a                            if (var_3f8 + 0x10 < 0)
00409939                                rbx_3 = 0;
0040933a                            else
0040933a                            {
00409347                                __rust_no_alloc_shim_is_unstable;
0040934a                                rbx_3 = 1;
00409357                                int64_t rax_48 = __rust_alloc_zeroed(var_3f8 + 0x10, 1);
00409357                                
00409360                                if (rax_48)
00409360                                {
00409377                                    memcpy(rax_48, var_400, var_3f8);
00409384                                    uint8_t aes::autodetect::aes_intrinsics::STORAGE::hc8673b1237a96b79_1 = aes::autodetect::aes_intrinsics::STORAGE::hc8673b1237a96b79;
00409389                                    uint8_t rax_50;
00409389                                    
00409389                                    if (aes::autodetect::aes_intrinsics::STORAGE::hc8673b1237a96b79_1
00409389                                            != 1 && (uint32_t)aes::autodetect::aes_intrinsics::STORAGE::hc8673b1237a96b79_1
00409389                                            == 0xff)
004093f9                                        rax_50 = aes::autodetect::aes_int...it_get::init_inner::hd807519274f9a4da();
004093f9                                    
00409401                                    if (aes::autodetect::aes_intrinsics::STORAGE::hc8673b1237a96b79_1
00409401                                            != 1 && ((uint32_t)aes::autodetect::aes_intrinsics::STORAGE::hc8673b1237a96b79_1
00409401                                            != 0xff || !rax_50))
004093a2                                        aes::soft::fixslice::aes256_key_schedule::hda8c6ed16e648178(
004093a2                                            &var_408, var_400);
00409401                                    else
00409401                                    {
00409410                                        _$LT$aes..ni..Aes256Enc$.....KeyInit$GT$::new::haaa3a7e26e4efd28(
00409410                                            &var_408, var_400);
00409429                                        aes::ni::aes256::inv_exp...cfbcbfed022f.llvm.3969909835275325008();
00409448                                        memcpy(&var_7d8, &var_408, 0xf0);
0040945b                                        memcpy(&var_408, &var_7d8, 0x1e0);
00409401                                    }
00409401                                    
0040947d                                    memcpy(&var_7d8, &var_408, 0x3c0);
00409487                                    int128_t var_418;
00409487                                    __builtin_strncpy(&var_418, "1234567890123456", 0x10);
0040949f                                    memcpy(&var_408, &var_7d8, 0x3d0);
004094a5                                    uint64_t r14_5 = var_3f8 >> 4;
004094b6                                    uint64_t r13_3 = (uint64_t)(uint32_t)var_3f8 & 0xf;
004094bd                                    fd = {0};
004094c2                                    int64_t r15_3 = rax_48 + (0x7ffffffffffffff0 & var_3f8);
004094d0                                    memcpy(&fd, r15_3, r13_3);
004094eb                                    memset(&var_968 + r13_3 + 0x10, 
004094eb                                        (uint32_t)(0x10 - (uint8_t)r13_3), 0x10 - r13_3);
004094f6                                    var_7d8 = fd;
004094fe                                    int64_t var_7c8_3 = rax_48;
00409506                                    (uint64_t)var_7c0 = rax_48;
0040950e                                    *(uint64_t*)((char*)var_7c0)[8] = r14_5;
00409526                                    void var_48;
00409526                                    fd = &var_48;
0040952b                                    int64_t var_950_1 = rax_48;
00409530                                    int64_t var_948_1 = rax_48;
00409535                                    uint64_t var_940 = r14_5;
00409547                                    _$LT$Alg$u20$as$u20$ciph...t_with_backend_mut::hd6fdacc991ffc37b(
00409547                                        &var_408, &fd);
0040954c                                    fd = &var_48;
00409551                                    uint64_t* var_950_2 = &var_7d8;
00409556                                    int64_t var_948_2 = r15_3;
0040956b                                    _$LT$Alg$u20$as$u20$ciph...t_with_backend_mut::h9dfecfe6a3f33a05(
0040956b                                        &var_408, &fd);
00409570                                    int64_t r14_6 = (uint64_t)var_7c0;
00409594                                    aes::autodetect::aes_intrinsics::STORAGE::hc8673b1237a96b79;
00409594                                    
0040959a                                    if (!r14_6)
0040959a                                    {
00409980                                        core::result::unwrap_failed::h1b5ed8541c7bebd6(
00409980                                            "called `Result::unwrap()` on an `Err` "
00409980                                        "value/home/quack/."
00409980                                        "rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/slice."
00409980                                        "rsPadErrorextern "Oh! A Good Old Hello World Binary "
00409980                                        "That Is Totally Innocent And Does Not St", 
00409980                                            0x2b, &var_7d8);
00409980                                        /* no return */
0040959a                                    }
0040959a                                    
004095a0                                    int64_t r13_6 =
004095a0                                        (*(uint64_t*)((char*)var_7c0)[8] + 1) << 4;
004095a7                                    int64_t rbx_4;
004095a7                                    
004095a7                                    if (r13_6 < 0)
0040998b                                        rbx_4 = 0;
004095a7                                    else
004095a7                                    {
004095ad                                        void* r15_4;
004095ad                                        
004095ad                                        if (!r13_6)
004095ad                                        {
004095da                                            r15_4 = 1;
004095e9                                        label_4095e9:
004095e9                                            memcpy(r15_4, r14_6, r13_6);
004095fc                                            __rust_dealloc(rax_48);
004095fc                                            
0040960a                                            if (rbx_2)
00409616                                                __rust_dealloc(var_400);
00409616                                            
00409627                                            if (rax_2)
00409633                                                __rust_dealloc(var_400);
00409633                                            
00409640                                            var_860 =
00409640                                                "Grandmas_Secret_Baking_Family_Recipe";
00409648                                            int64_t var_858_1 = 0x24;
0040965c                                            fd = &var_860;
00409668                                            char* var_950_3 = _$LT$$RF$T$u20$as$u20$co.....Display$GT$::fmt::h36fbadcb1601d653;
00409674                                            var_7d8 = &data_45fb38;
0040967c                                            var_7d0 = 2;
00409688                                            *(uint64_t*)((char*)var_7c0)[8] = 0;
00409694                                            int32_t* var_7c8_4 = &fd;
0040969c                                            (uint64_t)var_7c0 = 1;
004096b8                                            alloc::fmt::format::format_inner::h49a3ea498526530d(
004096b8                                                &var_408, &var_7d8);
004096c6                                            fd = var_408;
004096d3                                            uint64_t var_948_3 = var_3f8;
004096e2                                            var_7d8 = 0x1b600000000;
004096ea                                            int32_t var_7d0_1 = 0;
004096f5                                            int16_t var_7cc_1 = 0;
004096ff                                            *(uint8_t*)((char*)var_7d0_1)[1] = 1;
00409707                                            (uint8_t)var_7cc_1 = 1;
0040970f                                            *(uint8_t*)((char*)var_7d0_1)[3] = 1;
0040972c                                            std::fs::OpenOptions::_open::hce0f5e8979d4b5a1(
0040972c                                                &var_918, &var_7d8, var_950_3, var_3f8);
0040972c                                            
00409737                                            if ((uint32_t)var_918 == 1)
00409737                                            {
004099ac                                                var_7d8 = &data_45fb98;
004099b4                                                var_7d0_1 = 1;
004099c0                                                int64_t var_7c8_8 = 8;
004099cf                                                int128_t var_7c0_4 = {0};
004099df                                                std::io::stdio::_print::h2bb3f89bb77308e4(
004099df                                                    &var_7d8);
004099ea                                                std::process::exit::hc9c70ab8de590b08(1);
004099ea                                                /* no return */
00409737                                            }
00409737                                            
00409741                                            (uint32_t)var_8d8 =
00409741                                                *(uint32_t*)((char*)var_918)[4];
00409756                                            char const (** rax_57)[0x128] = std::io::Write::write_all::hb7d9f4951e8a6485(
00409756                                                &var_8d8, r15_4, r13_6);
00409756                                            
0040975e                                            if (rax_57)
0040975e                                            {
004099f2                                                var_878 = rax_57;
00409a02                                                var_918 = &var_878;
00409a0e                                                int64_t (* var_910_2)(int64_t* arg1, 
00409a0e                                                    int64_t* arg2) = _$LT$std..io..error..Err.....Display$GT$::fmt::hf3dbdd06f07e2f1c;
00409a1a                                                var_7d8 = &data_45fb58;
00409a22                                                var_7d0_1 = 2;
00409a2e                                                *(uint64_t*)((char*)var_7c0)[8] = 0;
00409a3a                                                int32_t** var_7c8_9 = &var_918;
00409a42                                                (uint64_t)var_7c0 = 1;
00409a56                                                std::io::stdio::_print::h2bb3f89bb77308e4(
00409a56                                                    &var_7d8);
00409a61                                                std::process::exit::hc9c70ab8de590b08(1);
00409a61                                                /* no return */
0040975e                                            }
0040975e                                            
00409764                                            var_918 = &fd;
00409770                                            int64_t (* var_910_1)(void* arg1, 
00409770                                                int64_t* arg2) = _$LT$alloc..string..Stri.....Display$GT$::fmt::h018e70d5162f383e;
0040977c                                            var_7d8 = &data_45fb78;
00409784                                            var_7d0_1 = 2;
00409790                                            *(uint64_t*)((char*)var_7c0)[8] = 0;
0040979c                                            int32_t** var_7c8_5 = &var_918;
004097a4                                            (uint64_t)var_7c0 = 1;
004097b8                                            std::io::stdio::_print::h2bb3f89bb77308e4(
004097b8                                                &var_7d8);
004097c5                                            int64_t result = close((uint32_t)var_8d8);
004097c5                                            
004097d3                                            if (fd)
004097df                                                result = __rust_dealloc(var_950_3);
004097df                                            
004097e8                                            if (r13_6)
004097f5                                                result = __rust_dealloc(r15_4);
004097f5                                            
00409803                                            if (!rax_4)
00409825                                                return result;
00409825                                            
0040980e                                            return __rust_dealloc(var_968);
004095ad                                        }
004095ad                                        
004095b6                                        __rust_no_alloc_shim_is_unstable;
004095b9                                        rbx_4 = 1;
004095c6                                        void* rax_55 = __rust_alloc(r13_6, 1);
004095c6                                        
004095cf                                        if (rax_55)
004095cf                                        {
004095d5                                            r15_4 = rax_55;
004095d8                                            goto label_4095e9;
004095cf                                        }
004095a7                                    }
004095a7                                    
0040999a                                    alloc::raw_vec::handle_error::h2c5ced866628b5d4(rbx_4);
0040999a                                    /* no return */
00409360                                }
0040933a                            }
0040933a                            
00409953                            alloc::raw_vec::handle_error::h2c5ced866628b5d4(rbx_3);
00409953                            /* no return */
00408fdd                        }
00408fdd                        
00408fee                        var_8c0_1 = 1;
00408ffe                        int64_t rax_25 = __rust_alloc(var_948, 1);
00408ffe                        
00409007                        if (rax_25)
00409007                        {
0040900d                            r15_1 = rax_25;
00409010                            goto label_409021;
00409007                        }
00408f85                    }
00408f85                    
0040992e                    alloc::raw_vec::handle_error::h2c5ced866628b5d4(var_8c0_1);
0040992e                    /* no return */
00408e6f                }
00408e6f                
00408e78                __rust_no_alloc_shim_is_unstable;
00408e7b                r14_1 = 1;
00408e89                rax_7 = __rust_alloc(var_810, 1);
00408e89                
00408e92                if (rax_7)
00408e92                    goto label_408ebf;
00408e61            }
00408e61            
00409905            alloc::raw_vec::handle_error::h2c5ced866628b5d4(r14_1);
00409905            /* no return */
00408d84        }
00408d84        
0040982d        var_7d8 = &data_45fc28;
00409835        var_7d0 = 1;
00409841        int64_t var_7c8_6 = 8;
00409850        int128_t var_7c0_2 = {0};
00409860        std::io::stdio::_print::h2bb3f89bb77308e4(&var_7d8);
00409868        std::process::exit::hc9c70ab8de590b08(0);
00409868        /* no return */
00408c60    }
```

- finds `Grandmas_Secret_Baking_Family_Recipe.txt` 
- performs SHA256 hash and compares against hardcoded value:
`502ff05a7b51b76e740b19cc4957ad118897a25becbb87fcb662a14b2e56a5d9`, if hash doesnt match, exits with `"File not found. Nothing to steal :("`
- if hash matches, calls `get_key_part()` function 8 times 
- uses assembled key for AES-256 encryption 


