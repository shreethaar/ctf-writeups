# Challenge 1: Minesweeper Championship Registration

**Description:** Welcome to the Fifth Annual Flare-On Challenge! The Minesweeper World Championship is coming soon and we found the registration app. You weren't *officially* invited but if you can figure out what the code is you can probably get in anyway. Good luck!

- Challenge File: `MinesweeperChampionshipRegistration.jar`

### Solution:
##### 1. Use JD-GUI to decompile the jar binary

![flare-on-5-1.png](flare-on-5-1.png)

Here is the `InviteValidator.class` code:
```java
import javax.swing.JOptionPane;  
  
public class InviteValidator {  
  public static void main(String[] args) {  
    String response = JOptionPane.showInputDialog(null, "Enter your invitation code:", "Minesweeper Championship 2018", 3);  
    if (response.equals("GoldenTicket2018@flare-on.com")) {  
      JOptionPane.showMessageDialog(null, "Welcome to the Minesweeper Championship 2018!\nPlease enter the following code to the ctfd.flare-on.com website to compete:\n\n" + response, "Success!", -1);  
    } else {  
      JOptionPane.showMessageDialog(null, "Incorrect invitation code. Please try again next year.", "Failure", 0);  
    }   
  }  
}
```

From the source code, the response should be equals to `GoldenTicket2018@flare-on.com`. Use this as the input to insert into the binary. 

![flare-on-5-2.png](flare-on-5-2.png)

**Flag:** `GoldenTicket2018@flare-on.com`


