---
title: The Mysterious Building
layout: default
---
# The Mysterious Building

Wow, that's a cool tower—I remember it well; saw it when I was on the metro one fine evening. But the building on the right... Something about its logo looks familiar, but I just can’t recall its name. Can you help me figure out the name of this mysterious building?

- Category: OSINT
- Challenge Image: OSINT-1.jpg

![[OSINT-1.jpg]]

### Solution:
##### 1. Use Google Images to find some clues about the tower

![[osint-1.png]]

From Google, the tower is Pitampura TV Tower and located at New Delhi, India. References: 
- [Flickr](https://www.flickr.com/photos/sachinkakkarphotography/7549037322)
- [Reddit](https://www.reddit.com/r/delhi/comments/z5ew8b/pitampura/)

##### 2. Discover the nearby building near the tower 
![[osint-2.png]]

There are numbers of buildings around the tower, also to note that from the challenge image, it seems that the buildings in around the range of 500m radius. With the use of LLM, it gives me a list of buildings:
```
- SD Tower Apartments
- Netaji Subhash Place Commercial Complex
- DDA HIG Housing Complex
- Sri Guru Gobind Singh College of Commerce
- Kohat Enclave Residential Buildings
- PP Tower
- Aggarwal Prestige Mall
```

From here, we can narrow it down. PP Tower is the one that is referred from the challenge image:
![[osint-3.png]]

GPS Coordinates: `8.6939448,77.1481033`
Name of Buidling: `PP Trade Centre`

**Flag:** `ACECTF{pp_trade_centre}

