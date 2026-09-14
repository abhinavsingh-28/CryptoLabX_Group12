| Step | Observation | Possible Substitution | Substitution Tested | Result | Decision |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | 'T' occurs most frequently in ciphertext | T &rarr; e | T &rarr; e | 'e' appears heavily as expected | Good decision |
| 2 | The 3-letter word "ZIT" occurs multiple times. Given T=e, "ZIe" is likely "The" | Z &rarr; t, I &rarr; h | Z &rarr; t, I &rarr; h | Reveals "the" frequently | Good decision |
| 3 | The 2-letter word "GY" appears; 'G' is frequent | G &rarr; o, Y &rarr; f | G &rarr; o, Y &rarr; f | Creates sensible words like "of" | Good decision |
| 4 | Pattern analysis shows "EE" (double E in ciphertext). Could be 'ss', 'tt', or 'll' | E &rarr; c | E &rarr; c (hypothesis) | Forms unreadable partial words | Reject |
| 5 | Re-evaluating "EE". If surrounding letters are known, it spells "messa_e" | E &rarr; g | E &rarr; g | Forms "message" | Good decision |