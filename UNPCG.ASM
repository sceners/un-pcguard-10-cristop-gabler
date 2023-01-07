; TITLE      : PC-Guard Unpacker (DOS)
; VERSION    : 1.0
; AUTHOR     : Christoph Gabler
; DATE       : 29th of april in 2000
; REQUEST    : Unpacker was requested by Sebastian
; PROG TYPE  : Hardware breakpoint unpacker + relocation rebuilder
; WORKS WITH : PC-Guard 3.xx (tested with 3.12C PRO and 3.20C PRO)
; USED MUSIC : Pantera[The great southern trendkill]

; ADDITIONAL INFORMATION :
; PC-Guard is the first encryption tool i discovered that can also be
; downloaded from such 'official' sites like download.com or softseek.com,
; due to this I first thought this encryptor is stronger then it really
; is, actually. Another interesting point is, that I have never seen any
; PC-Guard unpacker yet, strange, I have at least discovered 3-4 security
; wholes inside the envelope.
; The unpacker should be quiet generic and should unpack most PC-Guard
; versions. It can also unpack files protected with the shareware version
; which cannot run anymore because of an expired trial period ("No more
; executions!").
; Please remember that the option "ammount of layers" only specifies how
; many envelopes are used. For example, if the files was protected using
; "3 layers", you will have to run UNPCG.EXE 3 times to fully unpack it.

; greets to : Sebastian, Ralph, Eddy Hawk, u_schall, defiler, riDDLER
              The Cleric, The Rain, Merlin, dR.No, Gamumba, VAG, SVV...

; big shout outs to (where are u people?) :
              Loren Zen, Bane, Iosco & Mad S., Zenix, Egis, Lado, Luce....
              

code segment
org  100h
assume cs:code,ds:code
.386p

CHRiSTOPH:

jmp over_copyright
db 0Dh,0Ah,'*pURE nONSeNSE, pURE fUN*',0Dh,0Ah
over_copyright:

Call Clear_HW
Call Logo

Cmp DS:byte ptr [80h], 00
Jne OkPara

Mov Ah, 9
Mov Dx, Offset data_new
Int 21h
TillHere:

Call Clear_Hw
Mov Bx, 100h
Mov Cx, TillHere - CHRiSTOPH
KillMem2:
Mov CS:byte ptr [Bx], '?'
Inc Bx
Loop KillMem2
Mov Ax, 4C01h
Int 21h

DisplText:
Push Bx
Mov Al, CS:byte ptr [Bx]
Int 29h
Mov Cx, 0FFFFh
delay:
PushAd
PopAd
PushA
PopA
Loop delay

Pop Bx
Inc Bx
Cmp CS:byte ptr [Bx], '$'
Jne DisplText
Ret

Finish_Wait: Ret

OkPara:
Mov Bh, 00
Mov Bl, Ds:[80h]
Mov DS:byte ptr [81h+Bx], 00

;jmp dbgpoint2

Mov Bx, Offset hwbrktext
Call DisplText

dbgpoint2:
MainCode:

Mov Dx, offset HWBrkPoint0
Mov Ax, 2501h
Int 21h

Mov Dx, Cs
Mov Bx, 103h     ; CS:103h
Mov Ax, 0103h    ; Write, DR3
Call SetBreak
Mov Ax, 0003h    ; DR3
Call EnableBreak
Nop
BreakHere:
Nop

Mov Cx, 12h
Mov Al, 00
Mov Di, 100h
Cld
Repz
Stosb

Cmp CS:byte ptr [103h], 12h
Cmp Ax, 0BDFh
Jne BreakError

Mov Ah, 9
Mov Dx, Offset Bootup2
Int 21h
Jmp NormalGo

DoSecond_Pass:
Mov Ah, 9
Mov Dx, Offset DoingSecPass
Int 21h

NormalGo:
Call Clear_HW

; Open file, read file to 100h, Jmp to victim CS:IP

Mov Ax, 3D02h
Xor Cx, Cx
Mov Dx, 82h
Int 21h
Jc Open_Error
Mov Di, Ax

Mov Bx, Ax
mov al, 02
xor cx, cx
xor dx, dx
mov ah, 42h   ; Filepointer to end of file.
Int 21h       
Mov CS:word ptr [FileSize], Ax
Mov CS:word ptr [FileSize2], Dx
Mov CS:word ptr [FileSize3], Dx

Cmp Ax, 164Dh ; lame bypass
Je warning1

cwd
mov ax, 4200h                ; Filepointer to begin.
Xor Cx, Cx
Xor Dx, Dx
Mov Bx, Di
int 21h

Mov Ah, 3Fh
Mov Bx, Di
Mov Dx, Offset Image
Mov Cx, 7000h
Int 21h        ; Read header

Cmp DS:word ptr [Image], 'ZM'
Je Exefound
Cmp DS:word ptr [Image], 'MZ'
Je Exefound

Mov Ah, 9
Mov Dx, Offset ErrorMsg5
Int 21h
Mov Ax,4C01h
Int 21h

Exefound:
cwd
Mov Dx, CS:word ptr [Image+8]    ; Get .EXE header size
iMul Dx, 16d
Mov CS:word ptr [Exe_Header], Dx

Mov Ax, CS:word ptr [Image+10h]  ; Get .EXE SP value
Mov CS:word ptr [Exe_Sp], Ax

Mov Cx, CS:word ptr [Image+16h]  ; Get .EXE offset
Cmp CS:word ptr [Image+0Eh], Cx
Jne RealExe                      ;
Cmp CS:word ptr [Image+14h], 100h;
Jne RealExe                      ; > Check for real exe or converted
Cmp Ax, 0FFFEh
Jne RealExe

Mov CS:byte ptr [NoExe], 1       ;
Sub Cx, Cx                       ;
RealExe:
Mov CS:word ptr [Exe_Offset], Cx

Mov Dx, CS:word ptr [Exe_Header]
Xor Cx, Cx
Mov Bx, Di
mov ax, 4200h                     ; Filepointer to module start.
int 21h

Mov Dx, CS:word ptr [Image+0Eh]             ; Get .EXE Stack Segment
Mov CS:word ptr [Exe_SS], Dx

Mov Dx, CS:word ptr [Image+14h]             ; Get .EXE IP
Mov CS:word ptr [Exe_IP], Dx

Mov Ax, Cs
Mov Cx, CS:word ptr [Memory_Size]  ; 1000h
Add Ax, Cx
Mov CS:word ptr [Exe_CS], Ax

Mov EBP, CS:dword ptr [FileSize]
pUSH dS

Mov Si, CS:word ptr [Exe_CS]
Add Si, 10h
Mov Ds, Si
Cmp CS:byte ptr [NoExe], 1
Je OverNormal
Sub Si, 10h
OverNormal:
Mov CS:word ptr [Exe_Ds], Si

Xor Dx, Dx
Cmp CS:byte ptr [NoExe], 1
Jne OkAsAlways
Add Dx, 100h
OkAsAlways:

ReadFile:
Mov Ah, 3Fh
Mov Bx, Di
Mov Cx, 2000h
Int 21h        ; Read whole file to EXE_CS:EXE_IP
Add CS:word ptr [FileSize2], Ax

Mov Ax, Ds
Add Ax, 200h
Mov Ds, Ax
Cmp Ebp, 2000h
Jbe FinishRead
Sub Ebp, 2000h
Jmp ReadFile

FinishRead:
pOP dS

mov ax,4200h                           ; Filepointer to module start.
Cwd
Mov Dx, CS:word ptr [Exe_Header]
Xor Cx,Cx
Mov Bx, Di
int 21h

Mov Bx, Di
Mov Ah, 3Eh
Int 21h

Mov Es, CS:word ptr [Exe_DS]

Push Cs
Pop Ds

Xor Si, Si
Xor Di, Di
Mov Cx, 0FFh
Cld
REPZ
MOVSB                    ; Move CX bytes from DS:SI to ES:DI

Mov Bx, CS:word ptr [Exe_CS]
Add Bx, CS:word ptr [Exe_Offset]
Add Bx, 10h
Mov CS:word ptr [Exe_CS], Bx

Push Cs
Pop Ds

; PC-Guard detection

Cmp CS:word ptr [Exe_SP], 100h
Jne PCG_Error
Cmp CS:word ptr [Exe_IP], 0
Jne PCG_Error

Detected:

Push Cs
Pop Ds
Mov Dx, Offset HWBrkPoint
Mov Ax, 2501h
Int 21h

; Set up the hw breakpoint adress
Mov Dx, CS:word ptr [Exe_CS]
Mov Bx, 0025h   ; Break on write to CS:0025h  ; brk at stosb, mem clr
Mov Ax, 0101h   ; Write, DR1
Call SetBreak

Mov Ax, 0001h
Call EnableBreak

Cmp CS:byte ptr [Second_Pass], 0
Jne overthis1

Mov Ah, 9
Mov Dx, Offset PCG_Found
Int 21h

; Hook Int21h to bypass shareware limitation of pcguard
Push 0
Pop Fs
Mov Eax, FS:dword ptr [21h*4]
Mov CS:dword ptr [Old_Int21h], Eax
Mov FS:word ptr [21h*4], offset New_Int21h
Mov FS:word ptr [21h*4+2], CS

overthis1:

pUSH cS
pOP eS

Mov Ah,9
Mov Dx, Offset Success0
Int 21h

; Set up the registers!

Mov Ds, CS:word ptr [Exe_DS]
Push Ds
Pop Es

CLi
Mov Dx, Ds
Cmp CS:byte ptr [NoExe], 1
Je NoNormExe
Mov Dx, CS:word ptr [Exe_SS]   ; Header SS
Mov Ax, Cs
Add Dx, Ax
Add Dx, 1010h
NoNormExe:
Mov SS, Dx
Mov Sp, CS:word ptr [Exe_Sp]
STi

Mov DS:word ptr [80h], 00

Xor Bp, Bp
Mov Dx, Ds
Xor Ax, Ax
Xor Bx, Bx
Xor Cx, Cx
Mov Di, Sp
Mov Si, CS:word ptr [Exe_Ip]

; Launch victim file!
Jmp CS:dword ptr [Exe_Ip]

FileName db 'UNPACKED.EXE',00
Handle db 0,0
Old_Int21h dd 0
Signature db 0FFh,0BBh,48h,0B4h
First db 10h,' BREAKPOiNT REACHED',0Dh,0Ah,'$'
FirstPass db 'PASS1.DAT',0
Success0 db 'þ UNPACKiNG FiLE',0Dh,0Ah,'$'
Success db  'þ UNPACKED.EXE WRiTTEN AND DONE!',0Dh,0Ah,'$'
DoingSecPass db 0Dh,0Ah,'$'
Rebuilder db 'þ REBUiLDiNG RELOCATiON iTEMS',0Dh,0Ah,'$'
BootUp db 'NOT AVAILABLE',0Dh,0Ah,'$'
BootUp2 db 'AVAILABLE',0Dh,0Ah,'$'
PCG_Found     db 'þ PC-GUARD DETECTED',0Dh,0Ah,'$'
Reconstruct  db 'þ RECONSTRUCTiNG HEADER VALUES',0Dh,0Ah,'$'
hwbrktext db 'þ HARDWARE BREAKPOINTS ','$'
ErrorMsg db 0Dh,0Ah
         db 'Please boot to plain DOS, no exotic memory manager nor Windows allowed!',0Dh,0Ah,'$'
ErrorMsg3  db 'þ ERROR: FiLE NOT FOUND',0Dh,0Ah,'$'
ErrorMsg4  db 'þ ERROR: FiLE DOESN''T SEEM TO BE ENCRYPTED WiTH PC-GUARD!',0Dh,0Ah
           db '         (C)ontinue or (A)bort unpacking?',0Dh,0Ah,'$'
ErrorMsg5  db 'þ ERROR: PLEASE ONLY SPECiFY EXE FiLEZ!',0Dh,0Ah,'$'
ErrorMsg6  db 'þ WARNiNG: GUARD.EXE iS PROTECTED WiTH AN MODiFiED VERSiON OF PC-GUARD,',0Dh,0Ah
           db '           WHiCH LOADS THE IMAGE EXTERNALY FROM GUARD.DAT, PLEASE USE THE',0Dh,0Ah
           db '           TR SCRiPT FiLE ''UNPACK2'' TO UNPACK iT.',0Dh,0Ah,'$'
Memory_Size db 00,10h  ; 1000h

Warning1:
Mov Ah, 9
Mov Dx, Offset ErrorMsg6
Int 21h
Call Clear_HW
Mov Ax,4C01h
Int 21h

BreakError:
Mov Ah, 9
Mov Dx, Offset Bootup
Int 21h
Mov Ah, 9
Mov Dx, Offset ErrorMsg
Int 21h
Call Clear_HW
Mov Ax,4C01h
Int 21h
Open_Error:
Mov Ah, 9
Mov Dx, Offset ErrorMsg3
Int 21h
Call Clear_HW
Mov Ax,4C03h
Int 21h

PCG_Error:
Push Cs
Pop Ds

Mov Ah, 9
Mov Dx, Offset ErrorMsg4
Int 21h
Int16again:
Xor Ax, Ax
Int 16h
Cmp Al, 'c'
Je Detected
Cmp Al, 'a'
Je AbortUnpack
Jmp Int16again
AbortUnpack:
Mov Ax,4C01h
Int 21h

Exe_BP db 0,0
Clear_HW:
cli
xor eax,eax
mov dr7,eax     ; defeat hw breakpoints
mov dr0,eax
mov dr1,eax
mov dr2,eax
mov dr3,eax
sti
Ret

;++
; New Hardware breakpoint handler [dump/reconstruct]
;
Second_Pass db 00
HWBrkPoint2:

Mov CS:word ptr [Temp_DS], Ds
Mov CS:word ptr [Temp_ES], Es
Mov CS:word ptr [Temp_Di], Di

Pop Di ;ip
Pop Ds ;cs
Push Ds Di

Mov Ds, CS:word ptr [Temp_DS]
Mov Di, CS:word ptr [Temp_Di]
Mov Es, CS:word ptr [Temp_ES]

Inc CS:byte ptr [Second_Pass]

Mov CS:word ptr [Exe_BP], Bp
Pop Bx ; IP
Pop Ds ; CS
Push Ds Bx
Push Es
Pop Ds

Xor Esi, Esi
Mov Si, CS:word ptr [Temp_Cx] ; get filesize reg (stosb)
Add Si, 25d
Call Clear_Hw

Push Cs
Pop Ds

Mov Bp, Es

Mov Ah, 9
Mov Dx, Offset First
Int 21h

Cmp CS:byte ptr [Second_Pass], 01
Jne Last_Pass
Mov Dx, Offset FirstPass
Jmp Overnear
Last_Pass:
Mov Dx, Offset FileName
Overnear:
Xor Cx, Cx
Mov Ah, 3Ch      ; Create file "UNPACKED.EXE"
Int 21h
Mov Di, Ax

Mov Ah, 9
Mov Dx, Offset Reconstruct
Int 21h

; Reconstruct old header

Xor Ecx, Ecx
Mov Cx, CS:word ptr [Filesize]
Mov Ax, CS:word ptr [FileSize3]
Shl Eax, 10h
Add Ecx, Eax
Sub Ecx, ESi   ; Save filesize

Mov CS:word ptr [SaveSize], Cx
Push Cx
Shr Ecx, 10h
Mov CS:word ptr [FileSize3], Cx
Pop Cx

Mov Ax, Sp                          ;
Add Ax, 06h                         ; SP
Mov CS:word ptr [Image+10h], Ax     ;

;Add Cx, 28d ;? small bug with image size calculation when reloc rebuilding
;            ;? but is only a minor problem

; Image+2 and +4
Mov Ax, Cx
Mov Dx, Cx
And Ah, 1                       ; mod 512
Mov Cl, 9                       ; 2**9 = 512
Shr Dx, Cl                       
Inc Dx

Mov CS:word ptr [Image+2], Ax

Mov Cx, CS:word ptr [FileSize3]
Mov Bx, Cx
Imul Cx, 7Fh
Add Dx, Cx
Mov CS:word ptr [Image+4], Dx
Add CS:word ptr [Image+4], Bx

Pop Bx  ; Get Ip                    ;
Pop Ds  ; Get Cs                    ;
Push Ds Bx                          ; IP

Cmp DS:word ptr [Bx+7], 8EFAh
Jne Not_119found

Push Di Bp

Mov Ax, SS

Mov Dx, Es
Sub Ax, Dx
Sub Ax, 20h                         ; -10h   ;   -> SS
Mov CS:word ptr [Image+0Eh], Ax     ; SS     ;

Mov Dx, Es
Mov Cx, Ss
Cmp Cx, Dx
Jne ReallyAnExe0
Mov CS:word ptr [Image+16h], Dx
ReallyAnExe0:
Add CS:word ptr [Image+0Eh], 10h    ; -10h   ;   -> SS  

Mov Di, DS:word ptr [Bx+0Dh]
Mov Ax, DS:word ptr [Di+Bp]  ; Get SP
Mov CS:word ptr [Image+10h], Ax
Pop Bp Di
Mov Si, 1111h
Not_119found:

Cmp Si, 1111h
Je notdothis
Mov Ax, Ss                          ; -ES    ;
Mov Dx, Es
Sub Ax, Dx
Sub Ax, 20h                         ; -10h   ;   -> SS
Mov CS:word ptr [Image+0Eh], Ax     ; SS     ;

Mov Dx, Es
Mov Cx, Ss
Cmp Cx, Dx
Jne ReallyAnExe
Mov CS:word ptr [Image+16h], Dx
ReallyAnExe:
Add CS:word ptr [Image+0Eh], 10h    ; -10h   ;   -> SS  
notdothis:

;Mov Ax, DS:word ptr [Bx+3]          ; CS
Mov Ax, CS:word ptr [Temp_CS]
Sub Ax, 10h                         ;
Mov Dx, Es
Sub Ax, Dx
Mov CS:word ptr [Image+16h], Ax     ; -> CodeSegment Offset

Push Cs
Pop Ds
Mov Dx, Offset Image
Mov Cx, CS:word ptr [Exe_Header]
Mov Bx, Di

Mov Ah, 40h      ; Write old header to unpacked file
Int 21h

Cmp CS:byte ptr [Second_Pass], 02
Jne Last_Pass2

Mov CS:word ptr [Temp_DI], Di
Mov CS:word ptr [Temp_DS], Ds
Mov CS:word ptr [Temp_ES], Es
Mov CS:word ptr [Temp_BP], Bp

Mov Ah, 9
Mov Dx, Offset Rebuilder
Int 21h

; Rebuilding relocation items! [reloc rebuilder 1.0]

Mov Ax, 3D02h
Mov Dx, Offset FirstPass   ; Open "PASS1.DAT"
Int 21h
Mov Di, Ax

Mov CS:word ptr [RelocationNumber], 0000

mov ax,4200h                           ; Filepointer to module start.
Cwd
Mov Dx, CS:word ptr [Exe_Header]
Xor Cx,Cx
Mov Bx, Di
int 21h

Add Bp, 10h  ;
Mov Es, Bp   ;

Push Cs
Pop Ds
Xor Ecx, Ecx
Xor Eax, Eax
Mov Cx, CS:word ptr [SaveSize]
Sub Cx, CS:word ptr [Exe_Header]
Mov Ax, CS:word ptr [FileSize3]
Shl Eax, 10h
Add Eax, Ecx
Mov Ebp, Eax     ; EBP=Filesize

Cmp Ebp, 2000d
Jbe LastRead2

ReadFile2:
Mov Bx, Di
Mov Dx, Offset InternalBuffer
Mov Cx, 2000d
Mov Ah, 3Fh      ; Read file - for comparision
Int 21h

; Seek for relocation items...
Push Di Si
Mov Cx, 2000d
Xor Di, Di
Mov Si, Offset InternalBuffer

Find_the_difference:
Mov Al, ES:byte ptr [DI]  ; Look at internal unpack
Sub Al, CS:byte ptr [SI]  ; Look at PASS1.DAT unpack
Cmp Al, 1
Je Difference_Found
Back_Search:
Inc Si
Inc Di
Loop Find_the_difference
Jmp No_Item_Found

Difference_Found:
Inc CS:word ptr [RelocationNumber]
Mov Ax, CS:word ptr [Exe_Ds]
Add Ax, 10h
Sub ES:word ptr [DI], Ax           ; fix image reloc calc

Mov Bx, CS:word ptr [RelocationNumber]
Imul Bx, 4

Mov CS:word ptr [RelocBuffer+Bx-4], Di    ; header word (1)

Mov Ax, Es
Sub Ax, CS:word ptr [Exe_Ds]
Sub Ax, 10h
Mov CS:word ptr [RelocBuffer+Bx-2], Ax    ; header word (2)

Inc Si
Inc Di
Jmp Back_Search

No_Item_Found:

Cmp Bp, 1234h
Je FinishReloc

Mov Ax, Es    ;
Add Ax, 2000d/16d ;
Mov Es, Ax    ;

Pop Si Di
Sub Ebp, 2000d

Cmp Ebp, 2000d
Jbe LastRead2
Jmp ReadFile2
LastRead2:
Mov Bx, Di
Mov Dx, Offset InternalBuffer
Mov Cx, Bp
Mov Ah, 3Fh      ; Last read
Int 21h

Mov Cx, Bp
Mov Bp, 1234h
Push Di
Xor Di, Di
Mov Si, Offset InternalBuffer
Jmp Find_the_difference

FinishReloc:
Pop Di

Mov Ah, 3Eh
Mov Bx, Di
Int 21h

Mov Ah, 41h
Mov Dx, Offset FirstPass
Int 21h

Mov Di, CS:word ptr [Temp_DI]
Mov Ds, CS:word ptr [Temp_DS]
Mov Es, CS:word ptr [Temp_ES]
Mov Bp, CS:word ptr [Temp_BP]

Cmp CS:word ptr [RelocationNumber], 0
Je Last_Pass2

; Write new header data!

mov ax,4200h                           ; Filepointer to module start.
Cwd
Xor Dx, Dx
Xor Cx, Cx
Mov Bx, Di
int 21h

; calculate new header size
Mov Ax, CS:word ptr [RelocationNumber]
Imul Ax, 4
Add Ax, 1Ch
Shr Ax, 4
Cmp CS:word ptr [RelocationNumber], 1
Je Overthisr
Inc Ax
Overthisr:

; Al = New header size [08h]

Mov CS:word ptr [Image+8], Ax

Mov Cx, CS:word ptr [RelocationNumber]
Imul Cx, 4
Mov CS:word ptr [RelocSize], Cx
Xor Eax, Eax
Mov Ax, CS:word ptr [Exe_Header]
Add CS:dword ptr [SaveSize], EAx

Mov Ax, CS:word ptr [RelocationNumber]  ;  number of relocs
Mov CS:word ptr [Image+6], Ax           ;  located after 1Ch

Mov CS:word ptr [Image+18h], 1Ch        ;  offset of first reloc item

Mov Dx, Offset Image
Mov Cx, 1Ch
Mov Bx, Di
Mov Ah, 40h      ; Write old header to unpacked file (1Ch bytes)
Int 21h

Mov Bx, Di
Mov Cx, CS:word ptr [RelocationNumber]
Imul Cx, 4
Mov Dx, Offset RelocBuffer

Push Ds
Push Cs
Pop Ds

Cmp DS:word ptr [RelocBuffer], 1111h
Mov Ah, 40h      ; Write relocation items to unpacked file
Int 21h
Pop Ds

mov ax,4200h                           ; Filepointer to module start.
Cwd
Mov Dx, CS:word ptr [Image+8]
Imul Dx, 16d
Xor Cx, Cx
Mov Bx, Di
int 21h

Last_Pass2:


; Write file to disk!

Mov Dx, CS:word ptr [Exe_DS]
Add Dx, 10h      ; Point to DS+10:0000
Mov Ds, Dx       ;

Xor Ecx, Ecx
Xor Eax, Eax
Mov Cx, CS:word ptr [SaveSize]
Sub Cx, CS:word ptr [Exe_Header]
Mov Ax, CS:word ptr [FileSize3]
Shl Eax, 10h
Add Eax, Ecx
Mov Ebp, Eax     ; EBP=Filesize
Xor Edx, Edx
Mov Dx, CS:word ptr [RelocSize]   ;
Sub Ebp, EDx                      ;

Cmp Ebp, 2000h
Jbe LastWrite

WriteFile:
Mov Bx, Di
Xor Dx, Dx
Mov Cx, 2000h
Mov Ah, 40h      ; Write unpacked image to disk
Int 21h
Mov Ax, Ds
Add Ax, 200h
Mov Ds, Ax
Sub Ebp, 2000h

Cmp Ebp, 2000h
Jbe LastWrite
Jmp WriteFile
LastWrite:
Mov Bx, Di
Xor Dx, Dx
Mov Cx, Bp
Mov Ah, 40h      ; Last write to disk
Int 21h

Push Cs
Pop Ds

Mov Ah, 3Eh
Mov Bx, Di
Int 21h

Inc CS:word ptr [Memory_Size]

Cmp CS:byte ptr [Second_Pass], 01
Je AnotherPass

Mov Ah, 9
Mov Dx, Offset Success
Int 21h

Push 0
Pop Fs

exittodos:
Mov Ax, 4C00h
Int 21h

AnotherPass:
cli
mov sp, 0FFFEh
sti
Push Cs Cs Cs
Pop Ds Es Ss
Jmp DoSecond_Pass

; First Hardware BreakPoint
HWBrkPoint:
Mov CS:word ptr [Temp_DX], Dx
Mov CS:word ptr [Temp_DI], Di
Mov CS:word ptr [Temp_DS], Ds
Mov CS:word ptr [Temp_ES], Es
Mov CS:word ptr [Temp_BP], Bp

Mov CS:word ptr [Temp_Cx], Cx ; save filesize reg (stosb)

Mov Cx, 1000h
Pop Di ; IP
Pop Ds ; CS
Push Ds Di
Cmp DS:word ptr [Di], 0AAF3h
Jne invalid_brk

PushAD
xor bp, bp
Seek1:
Cmp DS:byte ptr [Di], 0EAh ; s33k for jmp far instr
Je Found1
Inc Di
Inc Bp
Loop Seek1
Found1: ;DS:DI now points to JMP FAR dword

Add CS:word ptr [Temp_Cx], Bp
Call Clear_HW

Mov Bx, DS:word ptr [DI+1]                  ; orig exe ip
Mov CS:word ptr [Image+14h], Bx             ; Save .EXE IP
Mov Dx, DS:word ptr [DI+3]                  ; orig exe cs
Mov CS:word ptr [Temp_CS], Dx
Mov Ax, 0000h    ; Exec, DR0
Call SetBreak
Mov Ax, 0000h    ; DR0
Call EnableBreak

Push Cs
Pop Ds
Mov Dx, offset HWBrkPoint2
Mov Ax, 2501h
Int 21h  ; pretty lazy idea to set another brk point at this point :)

PopAD
jmp @@9
invalid_brk:
Pop Dx    ;ip
Add Dx, 3 ;fix ret ip
Push Dx

@@9:
Mov Di, CS:word ptr [Temp_DI]
Mov Ds, CS:word ptr [Temp_DS]
Mov Es, CS:word ptr [Temp_ES]
Mov Bp, CS:word ptr [Temp_BP]
Mov Dx, CS:word ptr [Temp_DX]
Iret

New_INT21h:
Cmp Ah, 4Ch
Je unhook
Cmp Ah, 4Ah
Je bypass1
Cmp Ah, 48h
Je bypass1
Cmp Ah, 1Fh
Jne inv_brk
Cmp Dl, 3
Jne inv_brk
Mov CS:word ptr [Temp_Di], Di
Mov CS:word ptr [Temp_DS], Ds
Pop Di Ds ; cs:ip
Push Ds Di
Push Cx
Mov Cx, 500h
@@3:
Cmp DS:dword ptr [Di], 8BE90374h
Je @@4
Inc Di
Loop @@3
@@4:
Pop Cx
Mov DS:byte ptr [Di+1], 0
Mov Di, CS:word ptr [Temp_Di]
Mov Ds, CS:word ptr [Temp_DS]
inv_brk:
Jmp CS:dword ptr [Old_INT21h]
unhook:
Push Eax
Mov Eax, CS:dword ptr [Old_INT21h]
Mov FS:dword ptr [21h*4], Eax
Pop Eax
Jmp CS:dword ptr [Old_INT21h]
bypass1:
PushF
Call CS:dword ptr [Old_INT21h]
Mov Ax, Ds
Sub Ax, 318h
kickass:
clc
Iret

HWBrkPoint0:
Pop Bx ; IP
Push Bx
Mov Ax, 0BDFh
IRet

db 00,'[HW BRKPOiNT ENGiNE 1.0]',00

RelocationNumber db 0,0
RelocSize db 0,0
COM_CS db 0,0
FileSize db 0,0
FileSize2 db 0,0
FileSize3 db 0,0
SaveSize db 0,0
Exe_Ip db 0,0
Exe_Cs db 0,0
Exe_Header db 0,0
Exe_Offset db 0,0
Exe_SS db 0,0
Exe_Sp db 0,0
Exe_Ds db 0,0
NoExe db 0
Temp_DI db 0,0
Temp_DS db 0,0
Temp_ES db 0,0
Temp_BP db 0,0
Temp_Dx db 0,0
Temp_Cx db 0,0
Temp_CS db 0,0

;++
; Set hardware breakpoint
; Entry:
;	DX:BX	- segment:offset
;	AL	- num
;	AH	- type
;		    = 0 - execution
;		    = 1 - write
;		    = 3 - access
; Return:
;	NC	- if no error
;	CY	- if error occured
;--

        SetBreak proc

	pushad
	movzx	esi,dx
	shl	esi,4
	movzx	edi,bx
	add	esi,edi
	cmp	al,0
	jne	@@10
	mov	dr0,esi
@@10:	cmp	al,1
	jne	@@20
	mov	dr1,esi
@@20:	cmp	al,2
	jne	@@30
	mov	dr2,esi
@@30:	cmp	al,3
	ja	@@Err
	jne	@@40
	mov	dr3,esi
@@40:	mov	cl,al
	and	ah,0Fh			; Leave cond and len only
	movzx	ebx,ax
	xor	bl,bl
	shl	ebx,8
	mov	edx,0FFF0FFFFh
	shl	cl,2
	shl	ebx,cl
	shl	edx,cl			; Shift mask
	mov	bl,02h			; Global enable
	mov	dl,03h			; Mask both G&L enable bits
	shr	cl,1
	shl	bl,cl
	shl	dl,cl
	xor	dl,0FFh			; Invert mask
	mov	bh,2			; By setting this bit we make
					; CPU to point CS:IP exactly to
					; instruction that cause
					; breakpoint interrupt
	mov	dh,0FCh			; Mask is ready

	mov	eax,dr7
	and	eax,edx
	or	eax,ebx
	mov	dr7,eax
	popad
	clc
	ret
@@Err:	stc
	ret
	endp

;++
; Enable hardware breakpoint
; Entry:
;	AL	- num
; Return:
;	NC	- if no error
;	CY	- if error occured
; This procedure doesn't return error if al exceeds 3 and just
; enables nothing in this case.
;--

        EnableBreak proc
	push	eax			;
	push	ecx			;

	xor	ah,ah			;
	movzx	ecx,al			;
	shl	ecx,1			;
	inc	ecx			;
	mov	eax,dr7			;
	bts	eax,ecx			;
	mov	dr7,eax			;

	pop	ecx			;
	pop	eax			;
	ret				;
	endp				;

Logo:
		push	cs
		pop	ds
		jmp	short loc_1
data_1		db	7
data_2		db	0Dh, 0Ah, '$'
data_3		db	0FFh
		db	24h
loc_1:
		mov	si,offset data_3
loc_2:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_3			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_1
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_2
loc_3:
		mov	ah,9
		mov	dx,offset data_2	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_4
data_4		db	9
data_5		db	0Dh, 0Ah, '$'
data_6		db	20h
		db	0C4h
		db	40 dup (0C4h)
		db	24h
loc_4:
		mov	si,offset data_6
loc_5:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_6			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_4
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_5
loc_6:
		mov	ah,9
		mov	dx,offset data_5	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_7
data_8		db	0Fh
data_9		db	0Dh, 0Ah, '$'

data_10         db      20h
                db      0CDh
                db      4 dup (0CDh)
                db       10h, 10h
                db      ' UNPACKER FOR PC-GUARD 3.xx '
                db       11h, 11h,0CDh
                db      3 dup (0CDh)
                db      24h
loc_7:
		mov	si,offset data_10
loc_8:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_9			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_8
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_8
loc_9:
		mov	ah,9
		mov	dx,offset data_9	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_10
data_13		db	0Fh
data_14		db	0Dh, 0Ah, '$'
data_15		db	20h
		db	0CDh
		db	40 dup (0CDh)
		db	24h
loc_10:
		mov	si,offset data_15
loc_11:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_12			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_13
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_11
loc_12:
		mov	ah,9
		mov	dx,offset data_14	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_13
data_17		db	0Fh
data_18		db	0Dh, 0Ah, '$'
data_19		dw	2020h, 2020h, 2020h
		db	 20h,0FFh
                db      '  Coded by CHRiSTOPH / DTG'
		db	0FFh
		db	7 dup (0FFh)
		db	24h
loc_13:
		mov	si,offset data_19
loc_14:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_15			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_17
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_14
loc_15:
		mov	ah,9
		mov	dx,offset data_18	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_16
data_21		db	9
data_22		db	0Dh, 0Ah, '$'
data_23		db	20h
		db	0C4h
		db	40 dup (0C4h)
		db	24h
loc_16:
		mov	si,offset data_23
loc_17:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_18			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_21
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_17
loc_18:
		mov	ah,9
		mov	dx,offset data_22	; ('')
		int	21h			; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_19
data_25		db	0Fh
data_26		db	0Dh, 0Ah, '$'
data_27		db	0FFh
		db	24h
loc_19:
		mov	si,offset data_27
loc_20:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
		je	loc_21			; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
		mov	bl,data_25
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
		jmp	short loc_20
loc_21:
                mov     ah,9
                mov     dx,offset data_26       ; ('')
                int     21h                     ; DOS Services  ah=function 09h
						;  display char string at ds:dx
		push	cs
		pop	ds
		jmp	short loc_22
data_28		db	7
data_29		db	0Dh, 0Ah, '$'
data_new        db      'USAGE: UNPCG.EXE [FILE_TO_UNPACK]'
		db	'$'
loc_22:

		push	cs
		pop	ds
                jmp     short abc_1
abcd_1          db      7
abcd_2          db      0Dh, 0Ah, '$'
abcd_3          dw      4 dup (0FFFFh)
		db	0FFh, 24h
abc_1:
                mov     si,offset abcd_3
abc_2:
		mov	al,cs:[si]
		inc	si
		cmp	al,24h			; '$'
                je      abc_3                   ; Jump if equal
		mov	ah,9
		xor	bx,bx			; Zero register
                mov     bl,abcd_1
		mov	cx,1
		int	10h			; Video display   ah=functn 09h
						;  set char al & attrib bl @curs
						;   cx=# of chars to replicate
		mov	ah,3
		xor	bx,bx			; Zero register
		int	10h			; Video display   ah=functn 03h
						;  get cursor loc in dx, mode cx
		inc	dl
		mov	ah,2
		int	10h			; Video display   ah=functn 02h
						;  set cursor location in dx
                jmp     short abc_2
abc_3:
		mov	ah,9
                mov     dx,offset abcd_2        ; ('')
		int	21h			; DOS Services  ah=function 09h
Ret

OwnIntTable db 00,00,00,00,00,00,00
OldIntTable db 00,00,00,00,00,00,00

db 0Dh,0Ah,0Dh,0Ah,'This space is internally left free - ok, it''s pure lazyness of the coder! ;)',0Dh,0Ah
InternalBuffer db 2000d dup (00)

db 0Dh,0Ah,0Dh,0Ah,'Relocs temporary saved beyond this place :',0Dh,0Ah
RelocBuffer db 12000d dup (00)

Image:

db 'end'

code ends
end CHRiSTOPH
