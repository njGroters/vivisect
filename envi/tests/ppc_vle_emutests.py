GOOD_EMU_TESTS = 1
emutests = {
    #'e9f2': [{'setup': (('PC', 0x471450), ('LR', 0x313370)), 
    #    'tests': (('PC', 0x471434), ('LR', 0x471452))}],   # se_bl -0x1c

    #'e8eb': [{'setup': (('PC', 0x471450), ('LR', 0x313370 )), 
    #    'tests': (('PC', 0x471450), ('LR', 0x313370))}],   # se_b -0x2a

    '7CDF0214': [{'setup': (('r31', 4), ('r0', 16), ('XER', 0)),
        'tests': (('r6', 20), ('r31', 4), ('r0', 16), ('cr0', 0))}],   # add r6,r31,r0

}

