# reportAlertsOrionCytomicPanda
Script for create report in .csv with alerts of tool Orion by Cytomic Panda

For use set in terminal:

**1. Cookie**

	```-c, --cookie```
	[Nessesary] Cookie after login in https://orion.cytomicmodel.com
   
**2. Status**

	```-s, --status```
	Status 1 = In procces, Status 2 = Closed, all = not set
   
**3. Classification**

	```l, --classification```
	Unclassified = 0, Confirmed Attack = 1, Investigation with no attacks detected = 2, Potential Attack = 3, all = not set
  
**4. Priority**

	```-p, --priority```
	Critical = 1, High = 2, Normal = 3, Low = 4, all = not set

**5. Assigned**

	```-a, --assigned```
	For report to specific user(s) set email(s) in this list, Not Assigned = "none", all = not set
