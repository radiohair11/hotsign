# redo with name: typecode dictionary and typecode:params dictionary

LMOTS_typecodes = {'LMOTS_unused':0, \
                   'LMOTS_SHA256_N16_W1':1, \
                   'LMOTS_SHA256_N16_W2':2, \
                   'LMOTS_SHA256_N16_W4':3, \
                   'LMOTS_SHA256_N16_W8':4, \
                   'LMOTS_SHA256_N32_W1':5, \
                   'LMOTS_SHA256_N32_W2':6, \
                   'LMOTS_SHA256_N32_W4':7, \
                   'LMOTS_SHA256_N32_W8':8}

LMS_typecodes = {"LMS_unused":0, \
                 "LMS_SHA256_N32_H20":1, \
                 "LMS_SHA256_N32_H10":2, \
                 "LMS_SHA256_N32_H5":3,  \
                 "LMS_SHA256_N16_H20":4, \
                 "LMS_SHA256_N16_H10":5, \
                 "LMS_SHA256_N16_H5":6}

LMOTS_parms = {0: [0, 0], \
               1: [16, 1], \
               2: [16, 2], \
               3: [16, 4], \
               4: [16, 8], \
               5: [32, 1], \
               6: [32, 2], \
               7: [32, 4], \
               8: [32, 8]}

LMS_parms = {0: [0, 0], \
             1: [32, 20], \
             2: [32, 10], \
             3: [32, 5],  \
             4: [16, 20], \
             5: [16, 10], \
             6: [16, 5]}
