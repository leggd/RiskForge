#these are the scores for the CVSS, Criticality and exposure

def Risk_Forge_score (CVSS_score, CRITICALITY, EXPOSURE):
    #declaring the values for the cruciality and exposure
        CRITICALITY_VALUES = {
        "low": 0.5,
        "medium": 1,
        "high": 1.5,
        "critical": 2 }

        EXPOSURE_VALUES = {
                "private":0.75,
                "public": 1
                }

        #error handling 
        if not isinstance(CVSS_score, (int, float)):
         print (" invalid CVSS score")

        if CRITICALITY not in CRITICALITY_VALUES:
            print ("invalid criticality value")
            return None

        elif EXPOSURE not in EXPOSURE_VALUES:
            print ("invalid exposure value")  
            return None 

        else: #calculates the risk score and returs the value 
               #assigning the values to the variables
           Criticality_value = CRITICALITY_VALUES.get(CRITICALITY)
           exposure_value = EXPOSURE_VALUES.get(EXPOSURE)

           Risk_Forge_score = CVSS_score * Criticality_value * exposure_value
           return Risk_Forge_score
  
EXPOSURE = "public"
CRITICALITY = "high"
SCORE = 5.5

new_score = Risk_Forge_score(SCORE,CRITICALITY,EXPOSURE)
print(new_score)