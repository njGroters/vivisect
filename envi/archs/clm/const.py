from envi import *

mnems =     (
        'ad',
        'adc',
        'adci',
        'adcim',
        'adcm',
        'adf',
        'adfm',
        'adi',
        'adim',
        'adm',
        'an',
        'ani',
        'anm',
        'b',
        'bf',
        'bfm',
        'br',
        'bra',
        'brr',
        'c',
        'caa',
        'car',
        'cm',
        'cmf',
        'cmfm',
        'cmi',
        'cmim',
        'cmm',
        'cr',
        'dbrk',
        'di',
        'dmt',
        'dv',
        'dvf',
        'dvfm',
        'dvi',
        'dvim',
        'dvis',
        'dvism',
        'dvm',
        'dvs',
        'dvsm',
        'ei',
        'fti',
        'ftim',
        'ht',
        'ir',
        'itf',
        'itfm',
        'lds',
        'ldt',
        'ldw',
        'md',
        'mdf',
        'mdfm',
        'mdi',
        'mdim',
        'mdis',
        'mdism',
        'mdm',
        'mds',
        'mdsm',
        'mh',
        'ml',
        'ms',
        'mu',
        'muf',
        'mufm',
        'mui',
        'muim',
        'muis',
        'muism',
        'mum',
        'mus',
        'musm',
        'ng',
        'ngf',
        'ngfm',
        'ngm',
        'nt',
        'ntm',
        'or',
        'ori',
        'orm',
        're',
        'rf',
        'rl',
        'rli',
        'rlim',
        'rlm',
        'rmp',
        'rnd',
        'rndm',
        'rr',
        'rri',
        'rrim',
        'rrm',
        'sa',
        'sai',
        'saim',
        'sam',
        'sb',
        'sbc',
        'sbci',
        'sbcim',
        'sbcm',
        'sbf',
        'sbfm',
        'sbi',
        'sbim',
        'sbm',
        'ses',
        'sew',
        'sf',
        'sl',
        'sli',
        'slim',
        'slm',
        'smp',
        'sr',
        'sri',
        'srim',
        'srm',
        'sts',
        'stt',
        'stw',
        'wt',
        'xr',
        'xri',
        'xrm',
        'zes',
        'zew',
        )

ptypes = (
    "RA_RB_IM",
    "RA_RB_RC",
    "RA_RB_ME",
    "NO_RE",
    "CO",
    "CO_RA",
    "LO",
    "RA_IM",
    "RA_IM_AL",
    "RA_NO_FL",
    "RA_RB_LO_OP",
    "RA_RB_LO_VE_NO_FL",
    "RA_RB_LO_VE_NO_FL_AL",
    "RA_RB_OF_RE",
    "RA_RB_SH_VE",
    "RA_WI_FL",
)

ptcnt = 0
for pnm in ptypes:
    globals()[pnm] = ptcnt
    ptcnt += 1

Instructions = {
  'AD' :        (27, RA_RB_RC, ['000000', '0000'], 0),
  'ADC' :       (27, RA_RB_RC, ['0100000', '0000'], 0),
  'ADCI' :      (27, RA_RB_IM, ['0100000', '01'], 0),
  'ADCIM' :     (27, RA_RB_IM, ['0100010', '01'], 0),
  'ADCM' :      (27, RA_RB_RC, ['0100010', '0000'], 0),
  'ADF' :       (27, RA_RB_RC, ['0000001', '0000'], 0),
  'ADFM' :      (27, RA_RB_RC, ['0000011', '0000'], 0),
  'ADI' :       (27, RA_RB_IM, ['0000000', '01'], 0),
  'ADIM' :      (27, RA_RB_IM, ['0000010', '01'], 0),
  'ADM' :       (27, RA_RB_RC, ['0000010', '0000'], 0),
  'AN' :        (27, RA_RB_RC, ['0010100', '0000'], 0),
  'ANI' :       (27, RA_RB_IM, ['0010100', '01'], 0),
  'ANM' :       (27, RA_RB_RC, ['0010110', '0000'], 0),
  'B' :         (27, CO, ['110000'], IF_BRANCH | IF_COND),
  'BF' :        (27, RA_RB_LO_OP, ['101001100', '1000000'], 0),
  'BFM' :       (27, RA_RB_LO_OP, ['101001110', '1000000'], 0),
  'BR' :        (18, CO_RA, ['110010',"000"], IF_BRANCH | IF_COND),
  'BRA' :       (36, LO, ['111000100'], IF_BRANCH | IF_NOFALL),
  'BRR' :       (36, LO, ['111000000'], IF_BRANCH | IF_NOFALL),
  'C' :         (27, CO, ['110101'], IF_CALL | IF_COND),
  'CAA' :       (36, LO, ['111001100'], IF_CALL),
  'CAR' :       (36, LO, ['111001000'], IF_CALL),
  'CM' :        (18, RA_RB_SH_VE, ['10111000'], 0),
  'CMF' :       (18, RA_RB_SH_VE, ['10111010'], 0),
  'CMFM' :      (18, RA_RB_SH_VE, ['10111110'], 0),
  'CMI' :       (27, RA_IM, ['10111001'], 0),
  'CMIM' :      (27, RA_IM, ['10111101'], 0),
  'CMM' :       (18, RA_RB_SH_VE, ['10111100'], 0),
  'CR' :        (18, CO_RA, ['110111', '000'], IF_BRANCH | IF_COND),
  'DBRK' :      (18, NO_RE, ['111111111111111111'], 0),
  'DI' :        (18, RA_NO_FL, ['101000000101', '0'], 0),
  'DMT' :       (27, RA_RB_RC, ['0110100', '00000'], 0),
  'DV' :        (27, RA_RB_RC, ['0001100', '0000'], 0),
  'DVF' :       (27, RA_RB_RC, ['0001101', '0000'], 0),
  'DVFM' :      (27, RA_RB_RC, ['0001111', '0000'], 0),
  'DVI' :       (27, RA_RB_IM, ['0001100', '01'], 0),
  'DVIM' :      (27, RA_RB_IM, ['0001110', '01'], 0),
  'DVIS' :      (27, RA_RB_IM, ['0001100', '11'], 0),
  'DVISM' :     (27, RA_RB_IM, ['0001110', '11'], 0),
  'DVM' :       (27, RA_RB_RC, ['0001110', '0000'], 0),
  'DVS' :       (27, RA_RB_RC, ['0001100', '0010'], 0),
  'DVSM' :      (27, RA_RB_RC, ['0001110', '0010'], 0),
  'EI' :        (18, RA_NO_FL, ['101000000100', '0'], 0),
  'FTI' :       (27, RA_RB_LO_VE_NO_FL, ['101000101', '00000000'], 0),
  'FTIM' :      (27, RA_RB_LO_VE_NO_FL, ['101000111', '00000000'], 0),
  'HT' :        (18, NO_RE, ['101000000011000000'], IF_NOFALL),
  'IR' :        (18, NO_RE, ['101000000001000000'], IF_RET | IF_NOFALL),
  'ITF' :       (27, RA_RB_LO_VE_NO_FL, ['101000100', '00000000'], 0),
  'ITFM' :      (27, RA_RB_LO_VE_NO_FL, ['101000110', '00000000'], 0),
  'LDS' :       (54, RA_RB_OF_RE, ['1010100', '000'], 0),
  'LDT' :       (54, RA_RB_OF_RE, ['1010110', '000'], 0),
  'LDW' :       (54, RA_RB_OF_RE, ['1010101', '000'], 0),
  'MD' :        (27, RA_RB_RC, ['0010000', '0000'], 0),
  'MDF' :       (27, RA_RB_RC, ['0010001', '0000'], 0),
  'MDFM' :      (27, RA_RB_RC, ['0010011', '0000'], 0),
  'MDI' :       (27, RA_RB_IM, ['0010000', '10'], 0),
  'MDIM' :      (27, RA_RB_IM, ['0010010', '01'], 0),
  'MDIS' :      (27, RA_RB_IM, ['0010000', '11'], 0),
  'MDISM' :     (27, RA_RB_IM, ['0010010', '11'], 0),
  'MDM' :       (27, RA_RB_RC, ['0010010', '0000'], 0),
  'MDS' :       (27, RA_RB_RC, ['0010000', '0010'], 0),
  'MDSM' :      (27, RA_RB_RC, ['0010010', '0010'], 0),
  'MH' :        (27, RA_IM_AL, ['10001'], 0),
  'ML' :        (27, RA_IM_AL, ['10010'], 0),
  'MS' :        (27, RA_IM_AL, ['10011'], 0),
  'MU' :        (27, RA_RB_RC, ['0001000', '0000'], 0),
  'MUF' :       (27, RA_RB_RC, ['0001001', '0000'], 0),
  'MUFM' :      (27, RA_RB_RC, ['0001011', '0000'], 0),
  'MUI' :       (27, RA_RB_IM, ['0001000', '01'], 0),
  'MUIM' :      (27, RA_RB_IM, ['0001010', '01'], 0),
  'MUIS' :      (27, RA_RB_IM, ['0001000', '11'], 0),
  'MUISM' :     (27, RA_RB_IM, ['0001010', '11'], 0),
  'MUM' :       (27, RA_RB_RC, ['0001010', '0000'], 0),
  'MUS' :       (27, RA_RB_RC, ['0001000', '0010'], 0),
  'MUSM' :      (27, RA_RB_RC, ['0001010', '0010'], 0),
  'NG' :        (27, RA_RB_LO_OP, ['101001100', '0000000'], 0),
  'NGF' :       (27, RA_RB_LO_OP, ['101001101', '0000000'], 0),
  'NGFM' :      (27, RA_RB_LO_OP, ['101001111', '0000000'], 0),
  'NGM' :       (27, RA_RB_LO_OP, ['101001110', '0000000'], 0),
  'NT' :        (27, RA_RB_LO_OP, ['101001100', '0100000'], 0),
  'NTM' :       (27, RA_RB_LO_OP, ['101001110', '0100000'], 0),
  'OR' :        (27, RA_RB_RC, ['0011000', '0000'], 0),
  'ORI' :       (27, RA_RB_IM, ['0011000', '01'], 0),
  'ORM' :       (27, RA_RB_RC, ['0011010', '0000'], 0),
  'RE' :        (18, NO_RE, ['101000000000000000'], IF_RET | IF_NOFALL),
  'RF' :        (18, RA_NO_FL, ['101000001100', '0'], 0),
  'RL' :        (27, RA_RB_RC, ['0110000', '0000'], 0),
  'RLI' :       (27, RA_RB_IM, ['1000000', '00'], 0),
  'RLIM' :      (27, RA_RB_IM, ['1000010', '00'], 0),
  'RLM' :       (27, RA_RB_RC, ['0110010', '0000'], 0),
  'RMP' :       (27, RA_RB_LO_VE_NO_FL_AL, ['1010010', '0000000000'], 0),
  'RND' :       (27, RA_WI_FL, ['101001100', '000001100000'], 0),
  'RNDM' :      (27, RA_WI_FL, ['101001110', '000001100000'], 0),
  'RR' :        (27, RA_RB_RC, ['0110001', '0000'], 0),
  'RRI' :       (27, RA_RB_IM, ['1000001', '00'], 0),
  'RRIM' :      (27, RA_RB_IM, ['1000011', '00'], 0),
  'RRM' :       (27, RA_RB_RC, ['0110011', '0000'], 0),
  'SA' :        (27, RA_RB_RC, ['0101101', '0000'], 0),
  'SAI' :       (27, RA_RB_IM, ['0111101', '00'], 0),
  'SAIM' :      (27, RA_RB_IM, ['0111111', '00'], 0),
  'SAM' :       (27, RA_RB_RC, ['0101111', '0000'], 0),
  'SB' :        (27, RA_RB_RC, ['0000100', '0000'], 0),
  'SBC' :       (27, RA_RB_RC, ['0100100', '0000'], 0),
  'SBCI' :      (27, RA_RB_IM, ['0100100', '01'], 0),
  'SBCIM' :     (27, RA_RB_IM, ['0100110', '01'], 0),
  'SBCM' :      (27, RA_RB_RC, ['0100110', '0000'], 0),
  'SBF' :       (27, RA_RB_RC, ['0000101', '0000'], 0),
  'SBFM' :      (27, RA_RB_RC, ['0000111', '0000'], 0),
  'SBI' :       (27, RA_RB_IM, ['0000100', '01'], 0),
  'SBIM' :      (27, RA_RB_IM, ['0000110', '01'], 0),
  'SBM' :       (27, RA_RB_RC, ['0000110', '0000'], 0),
  'SES' :       (27, RA_RB_LO_VE_NO_FL_AL, ['101000000111', '00000'], 0),
  'SEW' :       (27, RA_RB_LO_VE_NO_FL_AL, ['1010000010000', '00000'], 0),
  'SF' :        (18, RA_NO_FL, ['101000001011', '0'], 0),
  'SL' :        (27, RA_RB_RC, ['0101000', '0000'], 0),
  'SLI' :       (27, RA_RB_IM, ['0111000', '00'], 0),
  'SLIM' :      (27, RA_RB_IM, ['0111010', '00'], 0),
  'SLM' :       (27, RA_RB_RC, ['0101010', '0000'], 0),
  'SMP' :       (27, RA_RB_ME, ['1010010', '1', '0000000'], 0),
  'SR' :        (27, RA_RB_RC, ['0101001', '0000'], 0),
  'SRI' :       (27, RA_RB_IM, ['0111001', '00'], 0),
  'SRIM' :      (27, RA_RB_IM, ['0111011', '00'], 0),
  'SRM' :       (27, RA_RB_RC, ['0101011', '0000'], 0),
  'STS' :       (54, RA_RB_OF_RE, ['1011000', '00'], 0),
  'STT' :       (54, RA_RB_OF_RE, ['1011010', '000'], 0),
  'STW' :       (54, RA_RB_OF_RE, ['1011001', '000'], 0),
  'WT' :        (18, NO_RE, ['101000000010000000'], 0),
  'XR' :        (27, RA_RB_RC, ['0011100', '0000'], 0),
  'XRI' :       (27, RA_RB_IM, ['0011100', '01'], 0),
  'XRM' :       (27, RA_RB_RC, ['0011110', '0000'], 0),
  'ZES' :       (27, RA_RB_LO_VE_NO_FL_AL, ['101000001001', '00000'], 0),
  'ZEW' :       (27, RA_RB_LO_VE_NO_FL_AL, ['101000001010', '00000'], 0),
}

inscnt = 0
for k,v in Instructions.items():
    globals()["INS_" + k.upper()] = inscnt
    inscnt += 1

REGISTER_MODE = 0
IMMEDIATE_MODE = 1

COND_NAMES = [
  "n", "e", "l", "le", "g", "ge", "no", "o", "ns", "s", "sl", "sle", "sg", "sge", None, ""
]

REGISTER_NAMES = [
    'r0',
    'r1',
    'r2',
    'r3',
    'r4',
    'r5',
    'r6',
    'r7',
    'r8',
    'r9',
    'r10',
    'r11',
    'r12',
    'r13',
    'r14',
    'r15',
    'r16',
    'r17',
    'r18',
    'r19',
    'r20',
    'r21',
    'r22',
    'r23',
    'r24',
    'r25',
    'r26',
    'r27',
    'r28',
    'st',
    'ra',
    'pc'
]
IF_SETFLAGS = 1<<8
IF_I        = 1<<9
IF_D        = 1<<10
