# Un-Pirateable Baking Game

- Category: reverse
- Difficulty: medium 
- Author: OddNorseman

I made a new video game inspired by my favorite YouTuber! It's amazing! But you need a license key to play it, and I haven't set up the webshop yet...
Something with Steam isn't working quite right yet either, so I've removed it for now. But at least the DRM is Un-piratable, so you have to wait to try it 😄

### Solution:

1. Decompile GameMaker 
- Use this [tool](https://github.com/UnderminersTeam/UndertaleModTool) and open data.win

2. Patch function that check license 

```
function isLicensed()
{
    if (file_exists("license.dat"))
    {
        var f = file_text_open_read("license.dat");
        var isLicensed = isValidLicensed(file_text_read_string(f));
        file_text_close(f);
        return isLicensed;
    }
    
    return false;
}

global.isPirated = true;

if (steam_initialised())
{
    global.isPirated = false;
    
    if (steam_get_persona_name() != "IGGGAMES")
        global.isPirated = true;
    
    if (steam_get_user_account_id() != 12345678)
        global.isPirated = true;
    
    if (steam_get_app_id() != 480)
        global.isPirated = true;
}

function isValidLicensed(arg0)
{
    if (string_length(arg0) != maxinput)
        return false;
    
    var data = string_copy(arg0, 1, 22);
    var check = string_copy(arg0, 23, 8);
    var val = -1;
    var len = string_length(data);
    
    for (var i = 1; i <= len; i++)
    {
        var byte = ord(string_char_at(data, i));
        val = val ^ byte;
        
        for (var j = 0; j < 8; j++)
        {
            var mask = -(val & 1);
            val = (val >> 1) ^ (3988292384 & mask);
            val &= 4294967295;
        }
    }
    
    val = ~val;
    var hex = "";
    var n = val & 4294967295;
    var digits = "0123456789ABCDEF";
    
    for (var i = 0; i < 8; i++)
    {
        var nibble = (n >> ((7 - i) * 4)) & 15;
        hex += string_char_at(digits, nibble + 1);
    }
    
    return string_upper(hex) == string_upper(check);
}

function checkLicense()
{
    if (isValidLicensed(global.userinput))
        room_goto_next();
}

global.userinput = "";
maxinput = 30;
blink = true;
blink_speed = 15;
alarm[0] = blink_speed;
enabled_keys = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

```

3. Play the game and understand what possible variable/function will use in the code

4. Reverse XOR function at gml_Object_End_Draw_64 function 

Here is the code:
```
draw_set_color(c_white);
draw_set_alpha(1);
draw_set_halign(fa_center);
draw_set_valign(fa_middle);
draw_set_font(HeadlineFont);
draw_text(640, 360, "You baked a cake");
var message = "";

if (global.isPirated)
    message = "And it tasted great!";
else
    message = "But you used salt instead of sugar...\nIt's terrible...";

draw_set_font(DefaultFont);
draw_text(640, 420, message);

if (global.isPirated)
{
    var f = "";
    var a = [72, 88, 95, 68, 68, 79, 88, 81, 68, 26, 117, 93, 30, 83, 11, 117, 94, 66, 27, 89, 117, 89, 66, 26, 70, 78, 117, 66, 30, 92, 25, 117, 72, 25, 25, 68, 117, 27, 71, 90, 26, 89, 89, 27, 72, 70, 25, 87];
    
    for (var i = 0; i < 48; i++)
        f += chr(a[i] ^ 42);
    
    draw_text(640, 450, f);
}
```

**Flag:** brunner{n0_w4y!_th1s_sh0ld_h4v3_b33n_1mp0ss1bl3}

