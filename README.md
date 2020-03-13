# rn-x509der-parser
Parsing X509 DER from base64 string

## Install
``` 
yarn add rn-x509der-parser 
```

## Usage

The X.509 DER encoding is based on TLV(type-length-value) type.
X509DERSpec class extends TLV interface and TLV has 4 properties.
buffer, identifier, contentLength, content
TLV.buffer is whole content of the code. It is a UInt8Array type.
Others are results of parsing. 
TLV.content may be a string or a boolean or a list of other TLV. 
If identifier.pc is Constructed then it's content will be a list of TLVs.
TLV content can be represented different way by id.tag type.

### TAG type

X509Paser represent the content of almost tag as just the buffer. 
OID, OCTET_STRING, BIT_STRING, BMP_STRING etc ...

| name    | tag encoding | represent |
| ------- | ------------ | --------- |
  EOC     | 0 | 
  BOOLEAN | 1 | boolean
  INTEGER | 2 | 
  BIT_STRING | 3 | 
  OCTET_STRING | 4 | 
  NULL | 5 | 
  OID | 6 | 
  Object_Descriptor | 7 | 
  EXTERNAL | 8 | 
  REAL | 9 | 
  ENUMERATED | 10 | 
  EMBEDDED_PDV | 11 | 
  UTF8String | 12 | string
  RELATIVE_OID | 13 | 
  TIME | 14 | 
  Reserved | 15 | 
  SEQUENCE | 16 | TVL 
  SET | 17 | TVL
  NumericString | 18 | 
  PrintableString | 19 | string
  T61String | 20 | 
  VideotexSt | 21 | 
  IA5String | 22 | string
  UTCTime | 23 | string
  GeneralizedTime | 24 | 
  GraphicString | 25 | 
  VisibleString | 26 | 
  GeneralString | 27 | 
  UniversalString | 28 | 
  CHARACTER_STRING | 29 | 
  BMPString | 30 | 
  DATE | 31 | 
  TIME_OF_DAY | 32 | 
  DATE_TIME | 33 | 
  DURATION | 34 | 
  OID_IRI | 35 | 
  RELATIVE_OID_IRI | 36 | 


### Import 


### Get X509DERSpec object

```typescript
import X509DERSpec from 'rn-x509der-parser';

... 

const pubKeyStirng: string = getBase64String();
const der = new X509DERSpec(pubKeyString);
console.log(der.toString());
```

<details><summary>RESULT</summary>
<p>

```
Certificate:
 Version: 
   INTEGER: : 02
 Serial Number: 26 EB 43 6E
 Signature: 
   OID: : 2A 86 48 86 F7 0D 01 01 0B
   NULL: : 
 Issuer: 
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 06
     PrintableString: : kr
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 0A
     UTF8String: : yessign
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 0B
     UTF8String: : AccreditedCA
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 03
     UTF8String: : yessignCA Class 2
 Validity: 
   UTCTime: : 200129150000Z
   UTCTime: : 210130145959Z
 Subject: 
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 06
     PrintableString: : kr
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 0A
     UTF8String: : yessign
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 0B
     UTF8String: : personal4IB
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 0B
     UTF8String: : WOORI
   SET: : 
    SEQUENCE: : 
     OID: : 55 04 03
     UTF8String: : ...
 Subject Public Key Info: 
   SEQUENCE: : 
    OID: : 2A 86 48 86 F7 0D 01 01 01
    NULL: : 
   BIT_STRING: : ...
 Issuer Unique Identifier: 
   SEQUENCE: : 
    SEQUENCE: : 
     OID: : 55 1D 23
     OCTET_STRING: : ...
    SEQUENCE: : 
     OID: : 55 1D 0E
     OCTET_STRING: : ...
    SEQUENCE: : 
     OID: : 55 1D 0F
     BOOLEAN: : true
     OCTET_STRING: : 
      BIT_STRING: : 06 C0
    SEQUENCE: : 
     OID: : 55 1D 20
     BOOLEAN: : true
     OCTET_STRING: : 
      SEQUENCE: : 
       SEQUENCE: : 
        OID: : 2A 83 1A 8C 9A 45 01 01 04
        SEQUENCE: : 
         SEQUENCE: : 
          OID: : 2B 06 01 05 05 07 02 02
          SEQUENCE: : 
           BMPString: : ...
         SEQUENCE: : 
          OID: : 2B 06 01 05 05 07 02 01
          IA5String: : ...
    SEQUENCE: : 
     OID: : 55 1D 11
     OCTET_STRING: : ...
    SEQUENCE: : 
     OID: : ...
     OCTET_STRING: : ...
    SEQUENCE: : 
     OID: : ...
     OCTET_STRING: : ...
 Subject Unique Identifierundefined
 Extensionsundefined

Certificate Signature Algorithm:: 
  OID: : ...
  NULL: : 
Certificate Signature:: ...
```


</p>
</details>

### Get Certificate

```typescript
const pubKeyStirng: string = getBase64String();
const der = new X509DERSpec(pubKeyString);
console.log(der.certificate.toString());
```

<details><summary>RESULT</summary>
<p>
This result is included the result of above.
  
```
Version: 
  INTEGER: : 02
Serial Number: 26 EB 43 6E
Signature: 
  OID: : 2A 86 48 86 F7 0D 01 01 0B
  NULL: : 
Issuer: 

...

```
</p>
</details>

### Decode TLV

You can also directly decode the TLV from buffer

```typescript
import {decodeTLV} from 'rn-x509der-parser';
import {Buffer} from 'buffer';

...

const buffer: Buffer = new Buffer(pubKeyString);
const tLVArray: TLV[] = decodeTLV(buffer);
```


## To do next

- represent the content of other tags ... 


## Reference 
https://en.wikipedia.org/wiki/X.509
https://en.wikipedia.org/wiki/X.690
