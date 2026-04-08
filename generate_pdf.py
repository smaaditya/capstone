#!/usr/bin/env python3
"""
Generate a comprehensive capstone project summary PDF.
"""
from fpdf import FPDF

class ProjectPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)
    
    def header(self):
        if self.page_no() > 1:
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(100, 100, 100)
            self.cell(0, 8, 'Secure Image Transmission on RISC-V: A Hardware Implementation of Hybrid Post-Quantum Protocol', align='C')
            self.ln(10)
            self.set_draw_color(0, 102, 204)
            self.set_line_width(0.5)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(3)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')
    
    def title_page(self):
        self.add_page()
        self.ln(40)
        self.set_font('Helvetica', 'B', 28)
        self.set_text_color(0, 51, 102)
        self.multi_cell(0, 14, 'SECURE IMAGE TRANSMISSION\nON RISC-V', align='C')
        self.ln(5)
        self.set_font('Helvetica', '', 16)
        self.set_text_color(0, 102, 153)
        self.multi_cell(0, 10, 'A Hardware Implementation of\nHybrid Post-Quantum Protocol', align='C')
        self.ln(10)
        self.set_draw_color(0, 102, 204)
        self.set_line_width(1)
        self.line(60, self.get_y(), 150, self.get_y())
        self.ln(10)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, 'Capstone Project - Complete Technical Summary', align='C')
        self.ln(15)
        self.set_font('Helvetica', '', 12)
        self.set_text_color(60, 60, 60)
        self.cell(0, 8, 'Team Members:', align='C')
        self.ln(8)
        self.set_font('Helvetica', 'B', 12)
        self.cell(0, 8, 'Mithun Aaditya S (22BEC1200)', align='C')
        self.ln(7)
        self.cell(0, 8, 'Shubanu M (22BEC1278)', align='C')
        self.ln(7)
        self.cell(0, 8, 'Harini Sakthivel (22BEC1285)', align='C')
        self.ln(12)
        self.set_font('Helvetica', '', 11)
        self.set_text_color(80, 80, 80)
        self.cell(0, 8, 'VIT Chennai | April 2026', align='C')
        self.ln(20)
        self.set_font('Helvetica', 'I', 10)
        self.set_text_color(100, 100, 100)
        self.multi_cell(0, 6, 'Standards: FIPS 203 (ML-KEM) | FIPS 197 (AES) | RS-232/UART | RISC-V ISA (RV32IM)', align='C')

    def chapter_title(self, title):
        self.add_page()
        self.set_font('Helvetica', 'B', 20)
        self.set_text_color(0, 51, 102)
        self.cell(0, 12, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(0, 102, 204)
        self.set_line_width(0.8)
        self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
        self.ln(8)
    
    def section_title(self, title):
        self.ln(4)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(0, 76, 153)
        self.cell(0, 9, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(3)
    
    def subsection_title(self, title):
        self.ln(2)
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(51, 51, 51)
        self.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
    
    def body_text(self, text):
        self.set_font('Helvetica', '', 10)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5.5, text)
        self.ln(2)
    
    def bullet(self, text, indent=10):
        x = self.get_x()
        self.set_font('Helvetica', '', 10)
        self.set_text_color(30, 30, 30)
        self.set_x(x + indent)
        self.cell(5, 5.5, '-')
        self.multi_cell(0, 5.5, text)
        self.ln(1)

    def bold_bullet(self, bold_part, text, indent=10):
        x = self.get_x()
        self.set_x(x + indent)
        self.set_font('Helvetica', '', 10)
        self.set_text_color(30, 30, 30)
        self.cell(5, 5.5, '-')
        self.set_font('Helvetica', 'B', 10)
        self.write(5.5, bold_part)
        self.set_font('Helvetica', '', 10)
        self.write(5.5, text)
        self.ln(6)

    def key_value(self, key, value, indent=10):
        x = self.get_x()
        self.set_x(x + indent)
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(30, 30, 30)
        self.write(5.5, f'{key}: ')
        self.set_font('Helvetica', '', 10)
        self.write(5.5, value)
        self.ln(6)

    def code_block(self, text):
        self.set_font('Courier', '', 8)
        self.set_text_color(40, 40, 40)
        self.set_fill_color(240, 240, 240)
        y_start = self.get_y()
        self.multi_cell(190, 4.5, text, fill=True)
        self.ln(3)

    def table_row(self, cells, widths, bold=False, header=False):
        h = 7
        style = 'B' if bold or header else ''
        if header:
            self.set_fill_color(0, 76, 153)
            self.set_text_color(255, 255, 255)
        else:
            self.set_fill_color(245, 245, 245)
            self.set_text_color(30, 30, 30)
        self.set_font('Helvetica', style, 9)
        for i, (cell, w) in enumerate(zip(cells, widths)):
            self.cell(w, h, str(cell), border=1, fill=header, align='C' if header else 'L')
        self.ln(h)

    def info_box(self, text):
        self.set_fill_color(230, 242, 255)
        self.set_draw_color(0, 102, 204)
        self.set_font('Helvetica', '', 10)
        self.set_text_color(0, 51, 102)
        x = self.get_x()
        y = self.get_y()
        self.rect(10, y, 190, 20, style='DF')
        self.set_xy(15, y + 3)
        self.multi_cell(180, 5.5, text)
        self.set_y(y + 22)


def main():
    pdf = ProjectPDF()
    pdf.alias_nb_pages()
    pdf.set_margins(10, 10, 10)
    
    # ========== TITLE PAGE ==========
    pdf.title_page()
    
    # ========== TABLE OF CONTENTS ==========
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 20)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(0, 12, 'TABLE OF CONTENTS', new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(0, 102, 204)
    pdf.line(10, pdf.get_y()+2, 200, pdf.get_y()+2)
    pdf.ln(10)
    
    toc_items = [
        ("1.", "Project Overview & Abstract", "3"),
        ("2.", "System Architecture", "4"),
        ("3.", "RISC-V Processor (Hornet Core)", "6"),
        ("  3.1", "Pipeline Architecture", "6"),
        ("  3.2", "ALU - Arithmetic Logic Unit", "8"),
        ("  3.3", "Control Unit", "9"),
        ("  3.4", "CSR Unit (Interrupts & Exceptions)", "10"),
        ("  3.5", "Forwarding & Hazard Detection", "11"),
        ("  3.6", "Load/Store Unit", "12"),
        ("  3.7", "Multiply/Divide Unit (M-Extension)", "12"),
        ("4.", "Peripheral Modules", "13"),
        ("  4.1", "Memory (Dual-Port SRAM)", "13"),
        ("  4.2", "UART Peripheral", "14"),
        ("  4.3", "Timer Registers (mtime/mtimecmp)", "14"),
        ("  4.4", "Loader/Bootloader Controller", "15"),
        ("  4.5", "Debug Interface", "15"),
        ("5.", "SoC Configurations", "16"),
        ("  5.1", "Barebones SoC (Simulation)", "16"),
        ("  5.2", "FPGA UART SoC (Deployment)", "16"),
        ("6.", "Boot Flow & Programming", "17"),
        ("7.", "CRYSTALS-Kyber (ML-KEM) Implementation", "18"),
        ("  7.1", "Kyber Algorithm Overview", "18"),
        ("  7.2", "Parameter Sets", "19"),
        ("  7.3", "NTT (Number-Theoretic Transform)", "20"),
        ("  7.4", "Polynomial & Polyvec Operations", "20"),
        ("  7.5", "IND-CPA Encryption Scheme", "21"),
        ("  7.6", "CCA-Secure KEM (FO Transform)", "22"),
        ("8.", "AES Symmetric Encryption", "23"),
        ("9.", "SHA-3 / FIPS 202 Hashing", "23"),
        ("10.", "Host Sender Application", "24"),
        ("11.", "Secure Receiver Application", "25"),
        ("12.", "Communication Protocol (UART)", "26"),
        ("13.", "Software Libraries", "27"),
        ("14.", "End-to-End Workflow", "28"),
        ("15.", "Security Analysis", "29"),
        ("16.", "File Structure Reference", "30"),
    ]
    
    for num, title, pg in toc_items:
        pdf.set_font('Helvetica', 'B' if not num.startswith(' ') else '', 11)
        pdf.set_text_color(30, 30, 30)
        w_num = 15
        pdf.cell(w_num, 7, num)
        pdf.cell(150, 7, title)
        pdf.set_font('Helvetica', '', 11)
        pdf.cell(0, 7, pg, align='R')
        pdf.ln(7)

    # ========== CHAPTER 1: PROJECT OVERVIEW ==========
    pdf.chapter_title('1. PROJECT OVERVIEW & ABSTRACT')
    
    pdf.section_title('1.1 Abstract')
    pdf.body_text(
        'This project implements a complete post-quantum secure image transmission system on a custom '
        'RISC-V processor. It combines CRYSTALS-Kyber (ML-KEM, FIPS 203) for quantum-resistant key '
        'encapsulation with AES (FIPS 197) for symmetric encryption, running on a 5-stage pipelined '
        'RV32IM processor deployed on a Xilinx Arty S7 FPGA. The system demonstrates a practical '
        'hardware implementation of hybrid post-quantum cryptography for embedded systems.'
    )
    
    pdf.section_title('1.2 Problem Statement')
    pdf.body_text(
        'The emergence of quantum computing poses an existential threat to current public-key cryptography. '
        "Shor's algorithm can break RSA and ECC in polynomial time on a sufficiently powerful quantum computer. "
        'NIST has standardized post-quantum cryptographic algorithms to address this threat. This project '
        'implements CRYSTALS-Kyber, selected by NIST for key encapsulation, on resource-constrained '
        'hardware (RISC-V soft-core on FPGA) to demonstrate feasibility of PQC in embedded systems.'
    )
    
    pdf.section_title('1.3 Key Objectives')
    pdf.bullet('Design and implement a custom 5-stage pipelined RISC-V (RV32IM) processor')
    pdf.bullet('Deploy the processor on Xilinx Arty S7 FPGA with UART communication')
    pdf.bullet('Implement CRYSTALS-Kyber (ML-KEM) key encapsulation mechanism')
    pdf.bullet('Implement AES-CBC symmetric encryption for bulk data encryption')
    pdf.bullet('Build a complete end-to-end secure image transfer pipeline')
    pdf.bullet('Use SHA-3 (FIPS 202) for key derivation and authentication tagging')
    
    pdf.section_title('1.4 Standards & Compliance')
    pdf.bold_bullet('FIPS 203 (ML-KEM): ', 'Module Lattice-Based Key Encapsulation Mechanism - the standard for Kyber')
    pdf.bold_bullet('FIPS 197 (AES): ', 'Advanced Encryption Standard - for symmetric encryption')
    pdf.bold_bullet('FIPS 202: ', 'SHA-3 Standard - for hashing (SHA3-256, SHAKE-128, SHAKE-256)')
    pdf.bold_bullet('RISC-V ISA: ', 'RV32IM - Base Integer (32-bit) + Multiply/Divide extension')
    pdf.bold_bullet('RS-232/UART: ', 'Serial communication between host and FPGA')

    # ========== CHAPTER 2: SYSTEM ARCHITECTURE ==========
    pdf.chapter_title('2. SYSTEM ARCHITECTURE')
    
    pdf.section_title('2.1 High-Level Architecture')
    pdf.body_text(
        'The system consists of two main components communicating over UART:'
    )
    pdf.body_text(
        '1) HOST SENDER (x86 PC): Receives the public key from the receiver, encapsulates a shared '
        'secret using Kyber, derives an AES key via SHA3-256, encrypts the image with AES-CBC, '
        'computes an authentication tag, and transmits the encrypted package.'
    )
    pdf.body_text(
        '2) SECURE RECEIVER (RISC-V on FPGA): Generates a Kyber key pair, sends the public key to '
        'the sender, receives the encrypted package, decapsulates the shared secret, verifies '
        'the authentication tag, decrypts the image using AES-CBC, and outputs the recovered image.'
    )
    
    pdf.section_title('2.2 Communication Flow')
    pdf.code_block(
        '  RECEIVER (RISC-V/FPGA)              HOST SENDER (x86 PC)\n'
        '  ========================             ====================\n'
        '  \n'
        '  crypto_kem_keypair()\n'
        '    -> pk.bin (800 bytes)\n'
        '    -> sk.bin (1632 bytes)\n'
        '                              --pk-->\n'
        '                                       crypto_kem_enc(ct, ss, pk)\n'
        '                                       SHA3-256(ss) -> AES key\n'
        '                                       RAND_bytes -> IV (16 bytes)\n'
        '                                       AES-CBC-encrypt(image)\n'
        '                                       SHA3-256(ss||iv||enc) -> tag\n'
        '                            <--package--\n'
        '  Parse: [ct_len|iv_len|enc_len|tag_len|ct|iv|enc|tag]\n'
        '  crypto_kem_dec(ss, ct, sk)\n'
        '  SHA3-256(ss) -> AES key\n'
        '  Verify tag: SHA3-256(ss||iv||enc) == received_tag\n'
        '  AES-CBC-decrypt(enc)\n'
        '  Remove PKCS7 padding\n'
        '    -> recovered image'
    )

    pdf.section_title('2.3 Package Wire Format')
    pdf.body_text('The encrypted package transmitted between sender and receiver follows this binary format:')
    widths = [35, 35, 35, 35, 50]
    pdf.table_row(['Field', 'Type', 'Size', 'Value', 'Description'], widths, header=True)
    pdf.table_row(['ct_len', 'uint32', '4 B', '768', 'Kyber ciphertext length'], widths)
    pdf.table_row(['iv_len', 'uint32', '4 B', '16', 'AES IV length'], widths)
    pdf.table_row(['enc_len', 'uint32', '4 B', 'varies', 'Encrypted data length'], widths)
    pdf.table_row(['tag_len', 'uint32', '4 B', '32', 'Auth tag length'], widths)
    pdf.table_row(['ct', 'bytes', '768 B', '-', 'Kyber ciphertext'], widths)
    pdf.table_row(['iv', 'bytes', '16 B', '-', 'AES CBC init vector'], widths)
    pdf.table_row(['enc', 'bytes', 'varies', '-', 'AES-CBC encrypted data'], widths)
    pdf.table_row(['tag', 'bytes', '32 B', '-', 'SHA3-256 auth tag'], widths)
    
    pdf.section_title('2.4 Cryptographic Stack')
    pdf.body_text('The system implements a layered cryptographic architecture:')
    pdf.bold_bullet('Layer 1 - Key Encapsulation: ', 'CRYSTALS-Kyber (ML-KEM, Kyber-512) provides quantum-resistant key exchange. Generates a 32-byte shared secret.')
    pdf.bold_bullet('Layer 2 - Key Derivation: ', 'SHA3-256 hashes the 32-byte shared secret into a 32-byte AES key (truncated to AES_KEYLEN for AES-128).')
    pdf.bold_bullet('Layer 3 - Symmetric Encryption: ', 'AES-CBC mode encrypts the image payload with PKCS7 padding.')
    pdf.bold_bullet('Layer 4 - Authentication: ', 'SHA3-256 computed over (shared_secret || IV || encrypted_data) provides integrity verification.')

    # ========== CHAPTER 3: RISC-V PROCESSOR ==========
    pdf.chapter_title('3. RISC-V PROCESSOR (HORNET CORE)')
    
    pdf.section_title('3.1 Pipeline Architecture')
    pdf.body_text(
        'The Hornet core is a 5-stage in-order pipelined processor implementing the RV32IM ISA '
        '(32-bit integer base + multiply/divide extension) with Machine-mode privilege level. '
        'It uses a Wishbone B4 pipelined bus interface.'
    )
    pdf.subsection_title('Key Specifications')
    pdf.key_value('ISA', 'RV32IM (Integer + Multiply/Divide)')
    pdf.key_value('Pipeline', '5-stage: IF -> ID -> EX -> MEM -> WB')
    pdf.key_value('Privilege Level', 'Machine mode (M-mode) only')
    pdf.key_value('Bus Interface', 'Wishbone B4 Pipelined')
    pdf.key_value('Register File', '32 x 32-bit registers (x0 hardwired to 0)')
    pdf.key_value('Reset Vector', 'Configurable (default 0x0, FPGA: 0x7400)')
    pdf.key_value('Branch Resolution', 'EX stage (2-cycle penalty)')
    pdf.key_value('Data Forwarding', 'MEM->EX and WB->EX paths')
    pdf.key_value('Hazard Handling', 'Load-use detection with 1-cycle stall')
    pdf.key_value('Multiply Latency', '3 cycles (pipelined Karatsuba)')
    pdf.key_value('Divide Latency', '~33 cycles (iterative restoring)')
    
    pdf.subsection_title('Pipeline Stages - Detailed Breakdown')
    pdf.body_text(
        'STAGE 1 - INSTRUCTION FETCH (IF): '
        'The PC register holds the current instruction address (configurable reset_vector). '
        'A 4-input mux chain selects the next PC: normal PC+4, stall (hold current PC), '
        'branch target address, or CSR interrupt/MRET return address. The fetched instruction '
        'and PC value are passed to the ID stage through the IFID pipeline register. '
        'The stage stalls on: hazard detection, MULDIV busy, misaligned access, data memory stall, or CSR stall. '
        'It flushes (inserts NOP) when a branch is taken or a CSR flush is triggered.'
    )
    pdf.body_text(
        'STAGE 2 - INSTRUCTION DECODE (ID): '
        'Decodes rs1, rs2, rd, CSR address, and immediate value from the instruction. '
        'Instantiates the control_unit and imm_decoder modules. Contains the 32x32-bit register file '
        'which writes on the negative clock edge (write-before-read) to avoid read-after-write hazards. '
        'A hazard mux zeroes out control signals when stalling is needed. Control signals are packed '
        'into pipeline fields: wb (7 bits), mem (3 bits), ex (21 bits) and passed to EX stage.'
    )
    pdf.body_text(
        'STAGE 3 - EXECUTE (EX): '
        'Instantiates the ALU, forwarding_unit, hazard_detection_unit, MULDIV_top, and load_store_unit. '
        '8 multiplexers handle forwarding, operand selection (register vs immediate vs PC), and CSR ALU path. '
        'The CSR ALU implements CSRRW (write), CSRRS (set bits), CSRRC (clear bits). '
        'Branch logic: take_branch = J | (B & aluout_EX[0]) where ALU produces 1/0 for branch conditions. '
        'Branch target is calculated and JALR clears the LSB. Misaligned instruction detection triggers exceptions.'
    )
    pdf.body_text(
        'STAGE 4 - MEMORY ACCESS (MEM): '
        'Passes ALU output, memory output, immediate, and control signals to WB stage. '
        'The load_store_unit handles byte/halfword/word alignment and misaligned access splitting. '
        'data_req_o is driven high for loads and stores. CSR flush can invalidate this stage.'
    )
    pdf.body_text(
        'STAGE 5 - WRITE BACK (WB): '
        'A 3-input WB mux selects: ALU output (R-type/I-type), memory output with sign extension (loads), '
        'or immediate value (LUI). Sign extension is applied for LB/LH (signed) vs LBU/LHU (unsigned). '
        'The selected value is written back to the register file and CSR unit.'
    )
    
    pdf.section_title('3.2 ALU - Arithmetic Logic Unit')
    pdf.body_text(
        'The ALU is a purely combinational module supporting 16 operations selected by a 4-bit function code. '
        'It takes two 32-bit operands (src1 and src2) and produces a 32-bit result.'
    )
    widths = [20, 35, 60, 75]
    pdf.table_row(['Code', 'Operation', 'Description', 'Used By'], widths, header=True)
    pdf.table_row(['0000', 'ADD', 'Addition', 'ADD, ADDI, Load/Store addr calc'], widths)
    pdf.table_row(['0001', 'SUB', 'Subtraction', 'SUB'], widths)
    pdf.table_row(['0010', 'XOR', 'Bitwise XOR', 'XOR, XORI'], widths)
    pdf.table_row(['0011', 'OR', 'Bitwise OR', 'OR, ORI'], widths)
    pdf.table_row(['0100', 'AND', 'Bitwise AND', 'AND, ANDI'], widths)
    pdf.table_row(['0101', 'SLTU', 'Set Less Than (unsigned)', 'SLTU, SLTIU, BLTU'], widths)
    pdf.table_row(['0110', 'SLT', 'Set Less Than (signed)', 'SLT, SLTI, BLT'], widths)
    pdf.table_row(['0111', 'SLL', 'Shift Left Logical', 'SLL, SLLI'], widths)
    pdf.table_row(['1000', 'SRL', 'Shift Right Logical', 'SRL, SRLI'], widths)
    pdf.table_row(['1001', 'SRA', 'Shift Right Arithmetic', 'SRA, SRAI'], widths)
    pdf.table_row(['1010', 'SEQ', 'Set if Equal', 'BEQ'], widths)
    pdf.table_row(['1011', 'SNE', 'Set if Not Equal', 'BNE'], widths)
    pdf.table_row(['1100', 'SGEU', 'Set >= (unsigned)', 'BGEU'], widths)
    pdf.table_row(['1101', 'SGE', 'Set >= (signed)', 'BGE'], widths)
    pdf.table_row(['1110', 'PC+4', 'Return address calc', 'JAL, JALR'], widths)
    pdf.table_row(['1111', 'PASS', 'Pass src2 through', 'LUI'], widths)

    pdf.section_title('3.3 Control Unit')
    pdf.body_text(
        'The control unit decodes the full RV32IM instruction set and generates all control signals '
        'for the pipeline. It extracts the opcode, funct3, funct7 fields and produces:'
    )
    pdf.bullet('ALU_func[3:0]: Selects ALU operation')
    pdf.bullet('CSR_ALU_func[1:0]: CSR operation type (RW/RS/RC)')
    pdf.bullet('EX_mux1..mux8: 8 multiplexer controls for the Execute stage')
    pdf.bullet('B (Branch) and J (Jump): Control flow flags')
    pdf.bullet('MEM_len[1:0]: Memory access length (byte/half/word)')
    pdf.bullet('MEM_wen: Memory write enable (active-low)')
    pdf.bullet('WB_rf_wen: Register file write enable (active-low)')
    pdf.bullet('WB_csr_wen: CSR write enable (active-low)')
    pdf.bullet('WB_mux[1:0]: Write-back source selector')
    pdf.bullet('muldiv_start/sel: M-extension multiply/divide start and select')
    pdf.bullet('illegal_instr, ecall_o, ebreak_o, mret_o: Exception signals')
    
    pdf.body_text('Supported instruction types:')
    pdf.bullet('R-type: ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND')
    pdf.bullet('I-type: ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI')
    pdf.bullet('Load: LB, LH, LW, LBU, LHU')
    pdf.bullet('Store: SB, SH, SW')
    pdf.bullet('Branch: BEQ, BNE, BLT, BGE, BLTU, BGEU')
    pdf.bullet('Jump: JAL, JALR')
    pdf.bullet('Upper Imm: LUI, AUIPC')
    pdf.bullet('M-Extension: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU')
    pdf.bullet('CSR: CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI')
    pdf.bullet('System: ECALL, EBREAK, MRET')

    pdf.section_title('3.4 CSR Unit (Interrupts & Exceptions)')
    pdf.body_text(
        'The CSR unit implements Machine-mode trap handling with a 2-state FSM (STAND_BY and S1). '
        'It manages all Control and Status Registers required for interrupt/exception handling.'
    )
    pdf.subsection_title('Implemented CSR Registers')
    widths_csr = [35, 60, 95]
    pdf.table_row(['Register', 'Address', 'Function'], widths_csr, header=True)
    pdf.table_row(['mstatus', '0x300', 'Machine status (MIE, MPIE, MPP fields)'], widths_csr)
    pdf.table_row(['mie', '0x304', 'Machine interrupt enable (MEIE, MTIE, MSIE + 16 fast IRQs)'], widths_csr)
    pdf.table_row(['mip', '0x344', 'Machine interrupt pending'], widths_csr)
    pdf.table_row(['mcause', '0x342', 'Trap cause (exception/interrupt code)'], widths_csr)
    pdf.table_row(['mtvec', '0x305', 'Trap vector base address (direct/vectored mode)'], widths_csr)
    pdf.table_row(['mepc', '0x341', 'Exception program counter (saved PC)'], widths_csr)
    pdf.table_row(['mscratch', '0x340', 'Scratch register for trap handlers'], widths_csr)
    
    pdf.subsection_title('Interrupt Priority (Highest to Lowest)')
    pdf.bullet('Fast Interrupts (bits 31:16 of mip) - with priority encoder for 16 fast IRQ lines')
    pdf.bullet('Machine External Interrupt (MEIP)')
    pdf.bullet('Machine Software Interrupt (MSIP)')
    pdf.bullet('Machine Timer Interrupt (MTIP)')
    pdf.bullet('Exceptions: Instruction access fault > Misaligned instruction > Illegal instruction > ECALL > EBREAK > Data access fault')
    
    pdf.body_text(
        'The CSR unit supports vectored mode (mtvec[0]=1) where the handler address is '
        'base + cause*4, enabling direct dispatch to interrupt-specific handlers. '
        'MRET handling restores mstatus.MIE from mstatus.MPIE and redirects PC to mepc. '
        'Per-stage flush signals cascade: csr_mem_flush -> csr_ex_flush -> csr_id_flush -> csr_if_flush.'
    )
    
    pdf.section_title('3.5 Forwarding & Hazard Detection')
    pdf.subsection_title('Forwarding Unit')
    pdf.body_text(
        'Detects Read-After-Write (RAW) data hazards and generates forwarding mux controls. '
        'Two forwarding paths are supported:'
    )
    pdf.bullet('MEM->EX forwarding (priority): Forwards result from MEM stage pipeline register')
    pdf.bullet('WB->EX forwarding: Forwards result from WB stage pipeline register')
    pdf.bullet('Register x0 is never forwarded (hardwired zero)')
    
    pdf.subsection_title('Hazard Detection Unit')
    pdf.body_text(
        'Detects load-use hazards (the one case forwarding cannot resolve): when a load instruction '
        'in EX stage is followed by a dependent instruction in ID stage. Smart opcode analysis '
        'determines which instructions actually use rs1 and rs2. Generates a 1-cycle stall bubble.'
    )
    
    pdf.section_title('3.6 Load/Store Unit')
    pdf.body_text(
        'Handles byte/halfword/word alignment for both loads and stores, including hardware support '
        'for misaligned accesses via 2-cycle split transactions.'
    )
    pdf.bullet('EX stage (store path): Generates word-aligned address, shifts store data and write mask based on addr[1:0], detects misalignment')
    pdf.bullet('MEM stage (load path): Extracts correct bytes from 32-bit memory word, reassembles misaligned loads from two memory reads')
    pdf.bullet('Supports all combinations: byte at any offset, halfword at offsets 0-3, word at offsets 0-3')
    
    pdf.section_title('3.7 Multiply/Divide Unit (M-Extension)')
    pdf.body_text(
        'Implements the full RV32M extension with separate multiply and divide datapaths.'
    )
    pdf.subsection_title('Multiplier (3-cycle latency)')
    pdf.bullet('2-stage pipelined multiplier using Karatsuba-like decomposition')
    pdf.bullet('Stage 1: Splits 32-bit operands into 4x8-bit chunks, computes 16 partial products (8x8->16 bit)')
    pdf.bullet('Stage 2: Combines partial products into 64-bit result (MHH, MHL, MLH, MLL)')
    pdf.bullet('Supports: MUL (lower 32), MULH (upper 32, signed x signed), MULHSU (signed x unsigned), MULHU (unsigned x unsigned)')
    
    pdf.subsection_title('Divider (~33-cycle latency)')
    pdf.bullet('Iterative restoring division algorithm')
    pdf.bullet('32 rounds: subtracts divisor from partial remainder, restores if negative')
    pdf.bullet('Shift-register builds quotient bit-by-bit')
    pdf.bullet('Produces 64-bit output: {quotient[31:0], remainder[31:0]}')
    pdf.bullet('Supports: DIV, DIVU, REM, REMU with proper sign handling')
    
    pdf.subsection_title('Fast-Result Optimization')
    pdf.body_text(
        'Special cases (operand = 0, 1, or -1) are handled combinationally without entering '
        'the MUL/DIV states, producing results in a single cycle.'
    )

    # ========== CHAPTER 4: PERIPHERALS ==========
    pdf.chapter_title('4. PERIPHERAL MODULES')
    pdf.body_text(
        'All peripherals use the Wishbone B4 bus interface with standard signals: '
        'cyc, stb, we, adr, dat_i, sel, stall, ack, dat_o, err.'
    )
    
    pdf.section_title('4.1 Memory - Dual-Port SRAM (memory_2rw_wb.v)')
    pdf.key_value('Type', 'Dual-port read/write SRAM with Wishbone interface')
    pdf.key_value('Port 0', 'Instruction fetch (read-only in practice)')
    pdf.key_value('Port 1', 'Data load/store (read/write)')
    pdf.key_value('Barebones Config', 'ADDR_WIDTH=11 -> 2048 words = 8 KB')
    pdf.key_value('FPGA Config', 'ADDR_WIDTH=13 -> 8192 words = 32 KB')
    pdf.key_value('Data Width', '32 bits with 4-byte write masks')
    pdf.body_text(
        'On FPGA builds, memory is pre-initialized from reset_handler.mem (words 7424-7487) and '
        'bootloader.mem (words 7488-8191) at startup using $readmemh. This provides a Harvard-style '
        'split memory architecture with independent instruction and data ports.'
    )
    
    pdf.section_title('4.2 UART Peripheral (uart_wb.v)')
    pdf.key_value('Baud Rate', '9600 (configurable via SYS_CLK_FREQ and BAUD parameters)')
    pdf.key_value('System Clock', '50 MHz (on FPGA), 100 MHz (simulation)')
    pdf.key_value('Frame Format', '1 start bit + 8 data bits + 1 stop bit')
    pdf.key_value('Address', '0x8010 on FPGA SoC')
    pdf.body_text(
        'Contains separate TX and RX sub-modules, each implemented as 5-state FSMs '
        '(IDLE -> START_BIT -> DATA_BITS -> STOP_BIT -> CLEANUP). The TX samples at mid-bit. '
        'Wishbone read returns: {8b0, 5b0, status[2:0], rx_byte[7:0], 8b0}. '
        'rx_irq_o is exported for fast interrupt system (wired to fast_irq[0] on FPGA). '
        'Based on nandland UART design.'
    )
    
    pdf.section_title('4.3 Timer Registers (mtime_registers_wb.v)')
    pdf.key_value('mtime', '64-bit auto-incrementing counter (every clock cycle)')
    pdf.key_value('mtimecmp', '64-bit software-writable compare value')
    pdf.key_value('Output', 'mtip_o asserted when mtime >= mtimecmp')
    pdf.key_value('Address', '0x8000 (mtime) / 0x8008 (mtimecmp) on FPGA')
    pdf.body_text(
        'Implements the RISC-V privileged specification timer registers. Both are memory-mapped '
        'and byte-selectable. The mtip_o output connects to the core CSR unit for timer interrupt generation.'
    )
    
    pdf.section_title('4.4 Loader/Bootloader Controller (loader_wb.v)')
    pdf.key_value('Type', 'UART-driven bootloader/reset controller')
    pdf.key_value('FSM', '5-state FSM triggered by UART byte sequences')
    pdf.key_value('Trigger Sequence', "'-' (0x2D) then '_' (0x5F) then 'p' (0x70)")
    pdf.key_value('Timeout', '2-second timeout releases reset after programming')
    pdf.key_value('Address', '0x8014 on FPGA')
    pdf.body_text(
        'Exposes a reset_cause register readable by the core (0 = power-on, 1 = UART-initiated load). '
        'Drives 3 debug LEDs indicating FSM state. Controls the core reset line independently '
        'so it can hold the core in reset while new firmware is loaded over UART.'
    )
    
    pdf.section_title('4.5 Debug Interface (debug_interface_wb.v)')
    pdf.key_value('Type', 'Simulation-only test pass/fail signaling')
    pdf.key_value('Address', '0x2010 on barebones SoC')
    pdf.body_text(
        'When the core writes value 1, prints "Success!" and terminates simulation. '
        'Any other value prints "Failure!" and terminates. Used by test programs to signal test results.'
    )

    # ========== CHAPTER 5: SOC CONFIGURATIONS ==========
    pdf.chapter_title('5. SOC CONFIGURATIONS')
    
    pdf.section_title('5.1 Barebones SoC (Simulation Target)')
    pdf.body_text('Minimal SoC for simulation and testing with 4 Wishbone slaves:')
    widths_mem = [50, 55, 85]
    pdf.table_row(['Address Range', 'Peripheral', 'Description'], widths_mem, header=True)
    pdf.table_row(['0x0000-0x1DFF', 'ROM (inst port)', '7.5 KB instruction memory'], widths_mem)
    pdf.table_row(['0x0000-0x1FFF', 'RAM (data port)', '8 KB data memory (overlaps ROM)'], widths_mem)
    pdf.table_row(['0x2000-0x200F', 'mtime/mtimecmp', 'Timer registers'], widths_mem)
    pdf.table_row(['0x2010', 'Debug Interface', 'Test pass/fail signaling'], widths_mem)
    
    pdf.body_text(
        'The testbench generates a 100 MHz clock, pre-loads memory from .data files, '
        'applies reset for 200ns, and includes commented-out interrupt test stimulus.'
    )
    
    pdf.section_title('5.2 FPGA UART SoC (Deployment Target)')
    pdf.body_text('Full FPGA-deployable SoC with 5 Wishbone slaves, targeting the Xilinx Arty S7 board:')
    widths_mem2 = [50, 55, 85]
    pdf.table_row(['Address Range', 'Peripheral', 'Description'], widths_mem2, header=True)
    pdf.table_row(['0x0000-0x7FFF', 'Memory', '32 KB instruction + data'], widths_mem2)
    pdf.table_row(['0x8000-0x800F', 'mtime/mtimecmp', 'Timer registers'], widths_mem2)
    pdf.table_row(['0x8010-0x8013', 'UART', 'Serial communication (9600 baud)'], widths_mem2)
    pdf.table_row(['0x8014', 'Loader', 'Reset controller'], widths_mem2)
    
    pdf.body_text(
        'Uses Xilinx clk_wiz_0 PLL to derive 50 MHz system clock from 100 MHz board oscillator. '
        'Core reset_vector is set to 0x7400 (reset handler location). '
        'UART RX interrupt wired to fast_irq[0] for interrupt-driven byte reception. '
        'FPGA pin assignments: 100 MHz clock (R2), reset switch (H14), UART RX/TX (V12/R12), 3 debug LEDs.'
    )

    # ========== CHAPTER 6: BOOT FLOW ==========
    pdf.chapter_title('6. BOOT FLOW & PROGRAMMING')
    
    pdf.body_text('The FPGA SoC implements a sophisticated multi-stage boot process:')
    
    pdf.subsection_title('Stage 1: Reset Handler (Address 0x7400)')
    pdf.body_text(
        'Pre-loaded in memory at synthesis time from reset_handler.mem. '
        'On power-on, the core starts executing from 0x7400 (reset_vector). '
        'The handler reads the loader reset_cause register at 0x8014. '
        'If reset_cause = 0 (power-on), it loops forever waiting for UART programming. '
        'If reset_cause != 0 (UART-loaded), it jumps to 0x7500 (bootloader).'
    )
    
    pdf.subsection_title('Stage 2: UART Programming')
    pdf.body_text(
        "The host sends the trigger sequence '-' then '_' then 'p' over UART. "
        'The loader FSM detects this sequence and releases the core reset. '
        'After a 2-second timeout (no more incoming bytes), the core restarts.'
    )
    
    pdf.subsection_title('Stage 3: Bootloader (Address 0x7500)')
    pdf.body_text(
        'Pre-loaded in memory from bootloader.mem. The bootloader initializes UART at 0x8010, '
        'prints "Waiting for opcodes...", and enables global interrupts and fast IRQ0. '
        'In the fast_irq0_handler, each received UART byte is written sequentially to memory '
        'starting at address 0x0000, loading the user program.'
    )
    
    pdf.subsection_title('Stage 4: User Program Execution')
    pdf.body_text(
        "Once the program is fully loaded, the host sends '-' 'p' again. "
        'The loader resets the core, which restarts at 0x7400, sees reset_cause=1, '
        'and jumps to 0x7500 -> 0x0000, executing the loaded program (e.g., secure_receiver).'
    )

    # ========== CHAPTER 7: KYBER ==========
    pdf.chapter_title('7. CRYSTALS-KYBER (ML-KEM) IMPLEMENTATION')
    
    pdf.section_title('7.1 Kyber Algorithm Overview')
    pdf.body_text(
        'CRYSTALS-Kyber is a lattice-based Key Encapsulation Mechanism (KEM) selected by NIST '
        'for standardization as ML-KEM (FIPS 203). Its security is based on the Module Learning '
        'With Errors (MLWE) problem, which is believed to be resistant to both classical and '
        'quantum attacks. The project uses the pq-crystals reference C implementation.'
    )
    pdf.body_text(
        'Kyber operates over the polynomial ring Rq = Zq[X]/(X^256 + 1) where q = 3329. '
        'The module rank k determines the security level (k=2 for Kyber-512, k=3 for Kyber-768, '
        'k=4 for Kyber-1024). This project primarily uses Kyber-512 (128-bit post-quantum security).'
    )
    
    pdf.subsection_title('Three Core Operations')
    pdf.bold_bullet('KeyGen(): ', 'Generates a public key pk (800 bytes) and secret key sk (1632 bytes). '
                    'Samples secret vector s and error vector e from centered binomial distribution, '
                    'computes public matrix A from seed via SHAKE-128, and outputs t = As + e.')
    pdf.bold_bullet('Encaps(pk): ', 'Takes public key, generates ciphertext ct (768 bytes) and shared secret ss (32 bytes). '
                    'Uses Fujisaki-Okamoto transform for CCA security.')
    pdf.bold_bullet('Decaps(ct, sk): ', 'Takes ciphertext and secret key, recovers shared secret ss (32 bytes). '
                    'Re-encrypts to verify ciphertext integrity (implicit rejection on failure).')
    
    pdf.section_title('7.2 Parameter Sets')
    widths_kyber = [38, 38, 38, 38, 38]
    pdf.table_row(['Parameter', 'Kyber-512', 'Kyber-768', 'Kyber-1024', 'Used In Project'], widths_kyber, header=True)
    pdf.table_row(['Module rank k', '2', '3', '4', '2 (Kyber-512)'], widths_kyber)
    pdf.table_row(['N (poly degree)', '256', '256', '256', '256'], widths_kyber)
    pdf.table_row(['q (modulus)', '3329', '3329', '3329', '3329'], widths_kyber)
    pdf.table_row(['eta1', '3', '2', '2', '3'], widths_kyber)
    pdf.table_row(['eta2', '2', '2', '2', '2'], widths_kyber)
    pdf.table_row(['PK size (bytes)', '800', '1184', '1568', '800'], widths_kyber)
    pdf.table_row(['SK size (bytes)', '1632', '2400', '3168', '1632'], widths_kyber)
    pdf.table_row(['CT size (bytes)', '768', '1088', '1568', '768'], widths_kyber)
    pdf.table_row(['SS size (bytes)', '32', '32', '32', '32'], widths_kyber)
    pdf.table_row(['Security level', '128-bit PQ', '192-bit PQ', '256-bit PQ', '128-bit PQ'], widths_kyber)
    
    pdf.section_title('7.3 NTT (Number-Theoretic Transform)')
    pdf.body_text(
        'The NTT is the core computational primitive enabling efficient polynomial multiplication in Kyber. '
        'It converts polynomial multiplication from O(n^2) to O(n log n) operations.'
    )
    pdf.subsection_title('Implementation Details (ntt.c)')
    pdf.bullet('Negacyclic NTT over Z_3329 for degree-256 polynomials')
    pdf.bullet('Primitive root of unity: omega = 17')
    pdf.bullet('128 pre-computed twiddle factors (zetas[]) in Montgomery form, bit-reversed order')
    pdf.bullet('Forward NTT: Cooley-Tukey butterfly, 7 layers (128 -> 2)')
    pdf.bullet('Inverse NTT: Gentleman-Sande butterfly, 7 layers (2 -> 128), final scaling by f = 1441')
    pdf.bullet('Base multiplication: Schoolbook in Z_q[X]/(X^2 - zeta) for NTT-domain polynomial multiplication')
    pdf.bullet('All arithmetic is 16-bit with Montgomery reduction (R = 2^16)')
    
    pdf.subsection_title('Montgomery Reduction (reduce.c)')
    pdf.body_text(
        'montgomery_reduce(a): Computes a * R^(-1) mod q where R = 2^16, q = 3329. '
        'Uses QINV = q^(-1) mod 2^16. Input range: {-q*2^15, ..., q*2^15 - 1}. '
        'Output range: {-q+1, ..., q-1}.'
    )
    pdf.subsection_title('Barrett Reduction (reduce.c)')
    pdf.body_text(
        'barrett_reduce(a): Centered representative modulo q using constant v = floor((2^26 + q/2) / q). '
        'Output range: {-(q-1)/2, ..., (q-1)/2}.'
    )
    
    pdf.section_title('7.4 Polynomial & Polyvec Operations')
    pdf.subsection_title('Polynomial Operations (poly.c)')
    pdf.bullet('poly_compress/decompress: Lossy compression to 4 bits (Kyber-512/768) or 5 bits (Kyber-1024) per coefficient')
    pdf.bullet('poly_tobytes/frombytes: Lossless 12-bit packing (384 bytes per polynomial)')
    pdf.bullet('poly_frommsg/tomsg: Encode/decode 32-byte message as polynomial (0 -> 0, 1 -> q/2 = 1665)')
    pdf.bullet('poly_getnoise_eta1/eta2: Sample from centered binomial distribution CBD_eta using SHAKE-256 PRF')
    pdf.bullet('poly_ntt/invntt_tomont: NTT/INTT wrappers with reduction')
    pdf.bullet('poly_basemul_montgomery: Pointwise multiplication using 64 basemul calls (one per degree-2 sub-polynomial)')
    pdf.bullet('poly_tomont: Convert to Montgomery domain (multiply by R^2 mod q)')
    pdf.bullet('poly_reduce: Barrett reduction on all 256 coefficients')
    pdf.bullet('poly_add/sub: Coefficient-wise operations')
    
    pdf.subsection_title('Centered Binomial Distribution (cbd.c)')
    pdf.bullet('cbd2 (eta=2): Processes 4-byte chunks, produces coefficients in {-2, -1, 0, 1, 2}')
    pdf.bullet('cbd3 (eta=3, Kyber-512): Processes 3-byte chunks, produces coefficients in {-3, ..., 3}')
    
    pdf.subsection_title('Polyvec Operations (polyvec.c)')
    pdf.bullet('Vector of k polynomials (k=2 for Kyber-512)')
    pdf.bullet('polyvec_compress/decompress: 10-bit (k=2,3) or 11-bit (k=4) lossy compression')
    pdf.bullet('polyvec_basemul_acc_montgomery: Inner product in NTT domain')
    pdf.bullet('polyvec_ntt/invntt_tomont: Apply NTT to all polynomials in vector')

    pdf.section_title('7.5 IND-CPA Encryption Scheme (indcpa.c)')
    pdf.body_text('The IND-CPA scheme is the core lattice-based encryption at the heart of Kyber:')
    pdf.subsection_title('Key Generation (indcpa_keypair)')
    pdf.body_text(
        'Sample secret s and error e from CBD_eta1. '
        'NTT both. Generate public matrix A from seed rho via SHAKE-128 + rejection sampling. '
        'Compute t = A*s + e. Public key pk = (t, rho). Secret key sk = s.'
    )
    pdf.subsection_title('Encryption (indcpa_enc)')
    pdf.body_text(
        'Sample r, e1 from CBD. Compute u = A^T * r + e1. '
        'Compute v = t^T * r + e2 + ceil(q/2) * m. '
        'Compress and pack (u, v) into ciphertext.'
    )
    pdf.subsection_title('Decryption (indcpa_dec)')
    pdf.body_text(
        'Decompress ciphertext. Compute m = v - s^T * u. '
        'Round to recover message bits.'
    )
    pdf.subsection_title('Matrix Generation (gen_matrix)')
    pdf.body_text(
        'Generates the public matrix A from a 32-byte seed using SHAKE-128 XOF (Extendable Output Function) '
        'and rejection sampling. Each coefficient is sampled as a 12-bit value < q = 3329.'
    )

    pdf.section_title('7.6 CCA-Secure KEM - Fujisaki-Okamoto Transform (kem.c)')
    pdf.body_text(
        'The FO transform converts the CPA-secure IND-CPA scheme into a CCA-secure KEM:'
    )
    pdf.subsection_title('Key Generation (crypto_kem_keypair)')
    pdf.body_text(
        'Calls indcpa_keypair_derand. Appends H(pk) and rejection value z to secret key.'
    )
    pdf.subsection_title('Encapsulation (crypto_kem_enc)')
    pdf.body_text(
        'Hashes (m || H(pk)) via hash_g to produce deterministic coins. '
        'Calls indcpa_enc with these coins. Shared secret = first 32 bytes of kr.'
    )
    pdf.subsection_title('Decapsulation (crypto_kem_dec)')
    pdf.body_text(
        'Re-encrypts to verify ciphertext integrity via constant-time comparison (verify.c). '
        'On failure: returns pseudorandom key rkprf(z, ct) (implicit rejection). '
        'On success: returns real shared secret via cmov (constant-time conditional copy). '
        'This prevents timing side-channel attacks.'
    )
    pdf.subsection_title('Constant-Time Operations (verify.c)')
    pdf.bullet('verify(a, b, len): Constant-time byte array comparison using XOR accumulation')
    pdf.bullet('cmov(r, x, len, b): Constant-time conditional copy with inline asm barrier')
    pdf.bullet('Critical for preventing timing side-channels in CCA decapsulation')

    # ========== CHAPTER 8: AES ==========
    pdf.chapter_title('8. AES SYMMETRIC ENCRYPTION')
    pdf.body_text(
        'The project uses the tiny-AES-C library (by kokke) for AES encryption. '
        'This is a lightweight, portable implementation suitable for embedded systems.'
    )
    pdf.key_value('Algorithm', 'AES (Advanced Encryption Standard, FIPS 197)')
    pdf.key_value('Mode', 'CBC (Cipher Block Chaining) with PKCS7 padding')
    pdf.key_value('Key Size', 'AES-128 (16-byte key) - configurable to AES-256')
    pdf.key_value('Block Size', '16 bytes (128 bits)')
    pdf.key_value('Source', 'tiny-AES-C (kokke/tiny-AES-c on GitHub)')
    
    pdf.subsection_title('Implementation Details (aes.c - 574 lines)')
    pdf.bullet('S-box and inverse S-box lookup tables (256 entries each)')
    pdf.bullet('Rcon (round constant) array for key expansion')
    pdf.bullet('KeyExpansion(): Generates Nb*(Nr+1) round keys from cipher key')
    pdf.bullet('Core transforms: SubBytes, ShiftRows, MixColumns, AddRoundKey (and inverses)')
    pdf.bullet('xtime(): GF(2^8) doubling for MixColumns')
    pdf.bullet('Cipher()/InvCipher(): Full encryption/decryption pipeline')
    pdf.bullet('AES_CBC_encrypt_buffer()/AES_CBC_decrypt_buffer(): CBC mode with IV chaining')
    pdf.bullet('Verified against NIST SP 800-38A test vectors')
    
    pdf.subsection_title('Usage in Project')
    pdf.body_text(
        'The sender encrypts image data using AES-CBC with the Kyber-derived key and a random 16-byte IV. '
        'PKCS7 padding is applied to handle non-block-aligned data. The receiver decrypts using the same '
        'key (recovered via Kyber decapsulation) and IV (transmitted in the package).'
    )

    # ========== CHAPTER 9: SHA-3 ==========
    pdf.chapter_title('9. SHA-3 / FIPS 202 HASHING')
    pdf.body_text(
        'SHA-3 (Keccak-based) is used throughout the project for multiple purposes:'
    )
    pdf.subsection_title('Functions Implemented (fips202.c - 775 lines)')
    widths_sha = [45, 30, 115]
    pdf.table_row(['Function', 'Output', 'Usage in Project'], widths_sha, header=True)
    pdf.table_row(['SHA3-256', '32 bytes', 'Key derivation: SHA3-256(shared_secret) -> AES key'], widths_sha)
    pdf.table_row(['SHA3-256', '32 bytes', 'Auth tag: SHA3-256(ss || iv || enc_data)'], widths_sha)
    pdf.table_row(['SHA3-512', '64 bytes', 'Kyber hash_g for FO transform'], widths_sha)
    pdf.table_row(['SHAKE-128', 'variable', 'Kyber matrix A generation (XOF)'], widths_sha)
    pdf.table_row(['SHAKE-256', 'variable', 'Kyber PRF for noise sampling'], widths_sha)
    
    pdf.subsection_title('Core: Keccak-f[1600] Permutation')
    pdf.body_text(
        'The implementation uses the Keccak-f[1600] state permutation with 25 x 64-bit state words '
        '(1600 bits total). 24 rounds of the permutation are applied. The implementation uses '
        'a "two-round unrolled" technique for performance. Based on public-domain code by '
        'Van Keer, Bernstein, and Schwabe.'
    )

    # ========== CHAPTER 10: HOST SENDER ==========
    pdf.chapter_title('10. HOST SENDER APPLICATION')
    pdf.body_text(
        'The host_sender program runs on the x86 host PC and handles the encryption side of the '
        'secure image transmission.'
    )
    
    pdf.subsection_title('Operation Modes')
    pdf.bold_bullet('File Mode: ', './host_sender <pk.bin> <image_in> <package_out> -- '
                    'Reads public key from file, reads image, encrypts, writes package to file.')
    pdf.bold_bullet('UART Mode: ', './host_sender uart <uart_base_hex> <image_in> -- '
                    'Receives public key over UART, encrypts, transmits package over UART.')
    
    pdf.subsection_title('Processing Pipeline')
    pdf.bullet('1. Read public key (800 bytes for Kyber-512) from file or UART')
    pdf.bullet('2. Read input image file into memory')
    pdf.bullet('3. Call crypto_kem_enc(ct, ss, pk) to encapsulate shared secret')
    pdf.bullet('4. Derive AES key: SHA3-256(ss) -> 32-byte hash -> truncate to AES_KEYLEN')
    pdf.bullet('5. Generate random 16-byte IV using OpenSSL RAND_bytes')
    pdf.bullet('6. Apply PKCS7 padding to image data')
    pdf.bullet('7. Encrypt padded image with AES-CBC using derived key and IV')
    pdf.bullet('8. Compute authentication tag: SHA3-256(ss || IV || encrypted_data)')
    pdf.bullet('9. Package: [ct_len|iv_len|enc_len|tag_len|ct|iv|enc|tag]')
    pdf.bullet('10. Write package to file or transmit over UART')
    
    pdf.subsection_title('Dependencies')
    pdf.bullet('Kyber ref library (kem.c, indcpa.c, poly.c, ntt.c, etc.)')
    pdf.bullet('tiny-AES-C (aes.c/aes.h)')
    pdf.bullet('FIPS 202 (fips202.c for SHA3-256)')
    pdf.bullet('OpenSSL (-lcrypto for RAND_bytes)')
    pdf.bullet('UART library (uart.c/uart.h for UART mode)')

    # ========== CHAPTER 11: SECURE RECEIVER ==========
    pdf.chapter_title('11. SECURE RECEIVER APPLICATION')
    pdf.body_text(
        'The secure_receiver program is designed to run either on the RISC-V processor (cross-compiled) '
        'or on a host PC for testing. It handles the decryption side.'
    )
    
    pdf.subsection_title('Operation Modes')
    pdf.bold_bullet('Key Generation: ', './secure_receiver (no args) -- Generates Kyber-512 keypair, '
                    'writes pk.bin (800 bytes) and sk.bin (1632 bytes)')
    pdf.bold_bullet('File Mode: ', './secure_receiver <package.bin> <output.img> -- '
                    'Reads secret key from sk.bin, parses package, decapsulates, verifies, decrypts')
    pdf.bold_bullet('UART Mode: ', './secure_receiver uart <base_hex> <output.img> -- '
                    'Transmits public key over UART, receives package over UART, then decrypts')
    
    pdf.subsection_title('Processing Pipeline')
    pdf.bullet('1. Read secret key sk.bin (1632 bytes for Kyber-512)')
    pdf.bullet('2. Parse package header: 4 x uint32_t (ct_len, iv_len, enc_len, tag_len)')
    pdf.bullet('3. Extract ciphertext, IV, encrypted data, and authentication tag')
    pdf.bullet('4. Call crypto_kem_dec(ss, ct, sk) to recover 32-byte shared secret')
    pdf.bullet('5. Derive AES key: SHA3-256(ss) -> truncate to AES_KEYLEN')
    pdf.bullet('6. Verify authentication tag: SHA3-256(ss || iv || enc_data) must match received tag')
    pdf.bullet('7. If tag mismatch: ABORT (data integrity compromised)')
    pdf.bullet('8. Decrypt with AES-CBC using derived key and received IV')
    pdf.bullet('9. Remove PKCS7 padding')
    pdf.bullet('10. Write plaintext image to output file')
    
    pdf.subsection_title('Build Targets (Makefile)')
    pdf.bold_bullet('all-host: ', 'Compiles for x86 using GCC, links OpenSSL (-lcrypto)')
    pdf.bold_bullet('cross: ', 'Cross-compiles for RISC-V using riscv32-unknown-elf-gcc with -march=rv32im')

    # ========== CHAPTER 12: UART PROTOCOL ==========
    pdf.chapter_title('12. COMMUNICATION PROTOCOL (UART)')
    
    pdf.section_title('12.1 UART Hardware Configuration')
    pdf.key_value('Baud Rate', '9600 bps')
    pdf.key_value('Data Bits', '8')
    pdf.key_value('Stop Bits', '1')
    pdf.key_value('Parity', 'None')
    pdf.key_value('Flow Control', 'None')
    pdf.key_value('Physical Interface', 'FPGA I/O pins (V12/RX, R12/TX on Arty S7)')
    
    pdf.section_title('12.2 Register Map')
    widths_uart = [40, 25, 40, 85]
    pdf.table_row(['Offset', 'R/W', 'Register', 'Description'], widths_uart, header=True)
    pdf.table_row(['+0', 'W', 'TX Data', 'Write byte to transmit'], widths_uart)
    pdf.table_row(['+1', 'R', 'RX Data', 'Read received byte'], widths_uart)
    pdf.table_row(['+2', 'R', 'Status', 'Bit 0: RX valid, Bit 1: TX active'], widths_uart)
    
    pdf.section_title('12.3 UART Mode Protocol')
    pdf.body_text('When operating in UART mode, the communication follows this sequence:')
    pdf.bullet('1. Receiver sends public key length (4 bytes, little-endian uint32)')
    pdf.bullet('2. Receiver sends public key (800 bytes for Kyber-512)')
    pdf.bullet('3. Sender receives public key and performs encapsulation + encryption')
    pdf.bullet('4. Sender sends 16-byte header (4 x uint32: ct_len, iv_len, enc_len, tag_len)')
    pdf.bullet('5. Sender sends ciphertext (768 bytes)')
    pdf.bullet('6. Sender sends IV (16 bytes)')
    pdf.bullet('7. Sender sends encrypted image data (variable length)')
    pdf.bullet('8. Sender sends authentication tag (32 bytes)')
    pdf.bullet('9. Receiver decapsulates, verifies tag, decrypts image')
    
    pdf.section_title('12.4 Interrupt-Driven Reception')
    pdf.body_text(
        'UART reception uses the fast IRQ mechanism of the Hornet core. '
        'The UART peripheral raises fast_irq[0] when a byte is received. '
        'The fast_irq0_handler ISR reads the byte and stores it in a buffer. '
        'This allows non-blocking reception while the processor continues execution.'
    )

    # ========== CHAPTER 13: SOFTWARE LIBRARIES ==========
    pdf.chapter_title('13. SOFTWARE LIBRARIES')
    
    pdf.section_title('13.1 UART Library (uart.c / uart.h)')
    pdf.bullet('uart_init(base_addr): Stores the base address of UART peripheral')
    pdf.bullet('uart_transmit_byte(): Polls TX status bit until idle, then writes byte')
    pdf.bullet('uart_transmit_string(buf, len): Sends buffer byte-by-byte')
    pdf.bullet('uart_receive_byte(): Polls RX status bit until data available, reads byte')
    pdf.bullet('uart_receive(buf, len): Receives len bytes into buffer')
    
    pdf.section_title('13.2 IRQ Library (irq.c / irq.h)')
    pdf.body_text('Provides the complete interrupt infrastructure for the Hornet core:')
    pdf.subsection_title('Macros (irq.h)')
    pdf.bullet('ENABLE_GLOBAL_IRQ() / DISABLE_GLOBAL_IRQ(): Set/clear MIE bit in mstatus')
    pdf.bullet('ENABLE_MTI() / DISABLE_MTI(): Machine timer interrupt enable/disable (bit 7 of mie)')
    pdf.bullet('ENABLE_MEI() / DISABLE_MEI(): Machine external interrupt enable/disable (bit 11)')
    pdf.bullet('ENABLE_FAST_IRQ(n) / DISABLE_FAST_IRQ(n): Fast interrupt n enable/disable (bit 16+n)')
    pdf.bullet('SET_MTVEC_VECTOR_MODE() / SET_MTVEC_DIRECT_MODE(): Configure trap vector mode')
    
    pdf.subsection_title('Vector Table and Handlers (irq.c)')
    pdf.body_text(
        'Defines weak default handler stubs for: mei_handler, mti_handler, msi_handler, exc_handler, '
        'fast_irq0_handler, fast_irq1_handler, direct_trap_handler. All are empty by default and '
        'overridable by application code. An inline assembly vector table provides jump instructions '
        'at exact offsets required by the RISC-V vectored interrupt specification.'
    )

    # ========== CHAPTER 14: END-TO-END WORKFLOW ==========
    pdf.chapter_title('14. END-TO-END WORKFLOW')
    
    pdf.section_title('14.1 Build Process')
    pdf.subsection_title('Host Sender (x86)')
    pdf.code_block(
        'cd kyber-main/host_sender\n'
        'make           # Compiles with gcc, links kyber ref, AES, UART, OpenSSL'
    )
    
    pdf.subsection_title('Secure Receiver (x86 testing)')
    pdf.code_block(
        'cd RISC-V-main/processor/fpga_uart/secure_receiver\n'
        'make all-host  # Compiles with gcc, links kyber ref, AES, OpenSSL'
    )
    
    pdf.subsection_title('Secure Receiver (RISC-V cross-compilation)')
    pdf.code_block(
        'cd RISC-V-main/processor/fpga_uart/secure_receiver\n'
        'make cross     # Compiles with riscv32-unknown-elf-gcc -march=rv32im'
    )
    
    pdf.section_title('14.2 File Mode Workflow')
    pdf.bullet('Step 1: Generate keys -- ./secure_receiver (creates pk.bin and sk.bin)')
    pdf.bullet('Step 2: Copy pk.bin to the host sender directory')
    pdf.bullet('Step 3: Encrypt image -- ./host_sender pk.bin image.png package.bin')
    pdf.bullet('Step 4: Copy package.bin to the secure receiver directory')
    pdf.bullet('Step 5: Decrypt image -- ./secure_receiver package.bin recovered.png')
    pdf.bullet('Step 6: Verify recovered.png matches original image.png')
    
    pdf.section_title('14.3 UART Mode Workflow')
    pdf.bullet('Step 1: Flash FPGA with the UART SoC bitstream')
    pdf.bullet('Step 2: Load secure_receiver onto RISC-V via UART bootloader')
    pdf.bullet('Step 3: Receiver generates Kyber keypair, transmits pk over UART')
    pdf.bullet('Step 4: Host sender receives pk, encapsulates, encrypts, transmits package')
    pdf.bullet('Step 5: Receiver receives package, decapsulates, verifies, decrypts')
    pdf.bullet('Step 6: Recovered image is available on the RISC-V system')

    # ========== CHAPTER 15: SECURITY ANALYSIS ==========
    pdf.chapter_title('15. SECURITY ANALYSIS')
    
    pdf.section_title('15.1 Post-Quantum Security')
    pdf.body_text(
        'The CRYSTALS-Kyber algorithm provides security against quantum computers based on the '
        'Module Learning With Errors (MLWE) problem. Kyber-512 offers NIST Security Level 1 '
        '(128-bit post-quantum security), equivalent to AES-128 against quantum attacks. '
        "Unlike RSA/ECC, Kyber is not vulnerable to Shor's algorithm."
    )
    
    pdf.section_title('15.2 CCA Security (Chosen-Ciphertext Attack)')
    pdf.body_text(
        'The Fujisaki-Okamoto transform applied in kem.c provides IND-CCA2 security. '
        'Decapsulation re-encrypts and compares ciphertexts using constant-time operations. '
        'On failure, a pseudorandom key is returned (implicit rejection) to prevent '
        'adaptive chosen-ciphertext attacks.'
    )
    
    pdf.section_title('15.3 Side-Channel Resistance')
    pdf.bullet('Constant-time comparison in verify() prevents timing attacks')
    pdf.bullet('Constant-time conditional move (cmov) with asm barrier prevents compiler optimization')
    pdf.bullet('Montgomery multiplication is inherently constant-time')
    pdf.bullet('Implicit rejection in KEM decapsulation prevents chosen-ciphertext side-channels')
    
    pdf.section_title('15.4 Data Integrity')
    pdf.body_text(
        'Authentication is provided by SHA3-256 computed over (shared_secret || IV || encrypted_data). '
        'This binds the authentication tag to the shared secret (known only to sender/receiver), '
        'the IV, and the ciphertext, preventing tampering or substitution attacks.'
    )
    
    pdf.section_title('15.5 Hybrid Approach Benefits')
    pdf.bullet('Post-quantum key exchange (Kyber) + Classical symmetric encryption (AES)')
    pdf.bullet('If Kyber is broken: AES still provides symmetric security (attacker needs key)')
    pdf.bullet('If AES is weakened: Kyber ensures the key exchange remains secure')
    pdf.bullet('Defense-in-depth against both classical and quantum adversaries')

    # ========== CHAPTER 16: FILE STRUCTURE ==========
    pdf.chapter_title('16. FILE STRUCTURE REFERENCE')
    
    pdf.section_title('16.1 RISC-V Processor (RISC-V-main/)')
    pdf.subsection_title('Core Modules (core/)')
    pdf.code_block(
        'core.v              - Top-level 5-stage pipelined processor\n'
        'core_wb.v           - Wishbone bus wrapper\n'
        'ALU.v               - 16-operation arithmetic logic unit\n'
        'control_unit.v      - Full RV32IM instruction decoder\n'
        'csr_unit.v          - CSR/interrupt/exception handler\n'
        'forwarding_unit.v   - RAW hazard forwarding (MEM->EX, WB->EX)\n'
        'hazard_detection_unit.v - Load-use hazard detection\n'
        'imm_decoder.v       - Immediate value decoder (all formats)\n'
        'load_store_unit.v   - Byte/half/word alignment + misaligned access\n'
        'muldiv/             - M-extension (Karatsuba MUL + restoring DIV)'
    )
    
    pdf.subsection_title('Peripherals (peripherals/)')
    pdf.code_block(
        'memory_2rw_wb.v     - Dual-port SRAM (Wishbone)\n'
        'uart_wb.v           - UART TX/RX peripheral\n'
        'mtime_registers_wb.v - 64-bit timer (mtime/mtimecmp)\n'
        'loader_wb.v         - UART bootloader/reset controller\n'
        'debug_interface_wb.v - Simulation debug interface'
    )
    
    pdf.subsection_title('SoC Configurations (processor/)')
    pdf.code_block(
        'barebones/barebones_wb_top.v  - Simulation SoC (8KB, 4 slaves)\n'
        'barebones/barebones_top_tb.v  - Testbench\n'
        'fpga_uart/fpga_top.v          - FPGA SoC (32KB, 5 slaves)\n'
        'fpga_uart/arty_s7.xdc         - FPGA constraints (Arty S7)'
    )
    
    pdf.subsection_title('Boot Firmware')
    pdf.code_block(
        'fpga_uart/reset_handler/  - Stage 1 boot (0x7400)\n'
        'fpga_uart/bootloader/     - Stage 2 UART loader (0x7500)\n'
        'fpga_uart/uart_main/      - Hello World demo\n'
        'fpga_uart/aes_main/       - AES-128 ECB demo over UART\n'
        'fpga_uart/muldiv_main/    - MUL/DIV test program\n'
        'fpga_uart/secure_receiver/ - Post-quantum secure receiver'
    )
    
    pdf.subsection_title('Libraries (lib/)')
    pdf.code_block(
        'uart.c / uart.h     - UART driver (transmit/receive)\n'
        'irq.c / irq.h       - Interrupt management (vector table, handlers)'
    )
    
    pdf.section_title('16.2 Kyber Implementation (kyber-main/)')
    pdf.subsection_title('Host Sender')
    pdf.code_block(
        'host_sender/host_sender.c  - Encryption + packaging program\n'
        'host_sender/Makefile        - Build with gcc + OpenSSL\n'
        'host_sender/host_debug.txt  - Debug output (shared secret, tag)'
    )
    
    pdf.subsection_title('Kyber Reference Library (kyber-main/ref/)')
    pdf.code_block(
        'kem.c          - CCA-secure KEM (FO transform)\n'
        'indcpa.c       - IND-CPA lattice encryption core\n'
        'ntt.c          - Number-Theoretic Transform\n'
        'poly.c         - Polynomial operations (256 coefficients)\n'
        'polyvec.c      - Vector-of-polynomials operations\n'
        'cbd.c          - Centered binomial distribution\n'
        'reduce.c       - Montgomery/Barrett reduction\n'
        'verify.c       - Constant-time comparison/move\n'
        'fips202.c      - SHA-3/SHAKE (Keccak)\n'
        'symmetric-shake.c - Symmetric primitives wrapper\n'
        'randombytes.c  - Random number generation\n'
        'params.h       - Kyber parameter definitions'
    )
    
    pdf.section_title('16.3 Test Programs')
    pdf.code_block(
        'test/aes/       - AES-128 ECB test on RISC-V\n'
        'test/bubble_sort/ - Sorting algorithm test\n'
        'test/muldiv/    - Multiply/divide verification\n'
        'test/crt0.s     - C runtime startup\n'
        'test/linksc.ld  - Linker script (ROM: 7.5KB, RAM: 508B)'
    )

    # ========== FINAL PAGE ==========
    pdf.add_page()
    pdf.ln(20)
    pdf.set_font('Helvetica', 'B', 16)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(0, 12, 'Summary of Key Achievements', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_font('Helvetica', '', 11)
    pdf.set_text_color(30, 30, 30)
    
    achievements = [
        'Custom 5-stage pipelined RISC-V (RV32IM) processor designed in Verilog',
        'Full Wishbone B4 bus interconnect with 5 peripheral slaves',
        'Hardware-supported misaligned memory access and M-extension (multiply/divide)',
        'Machine-mode interrupt/exception handling with 16 fast IRQ lines and vectored mode',
        'Dual-port SRAM (32KB) with UART-based bootloader for FPGA deployment',
        'CRYSTALS-Kyber (ML-KEM) post-quantum key encapsulation mechanism',
        'AES-CBC symmetric encryption with SHA3-256 key derivation and authentication',
        'Complete end-to-end secure image transfer pipeline (host sender + RISC-V receiver)',
        'Support for both file-based and UART-based communication modes',
        'Cross-compilation toolchain for RISC-V (riscv32-unknown-elf-gcc)',
        'FPGA deployment on Xilinx Arty S7 with PLL, UART, timer, and LED debug',
        'Multi-stage boot: reset handler -> bootloader -> user program',
        'Compliance with FIPS 203 (ML-KEM), FIPS 197 (AES), FIPS 202 (SHA-3), RISC-V ISA',
    ]
    
    for i, a in enumerate(achievements, 1):
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(10, 8, f'{i}.')
        pdf.set_font('Helvetica', '', 11)
        pdf.multi_cell(0, 8, a)
        pdf.ln(1)
    
    pdf.ln(15)
    pdf.set_draw_color(0, 102, 204)
    pdf.set_line_width(0.8)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(8)
    pdf.set_font('Helvetica', 'I', 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, 'End of Document', align='C')
    
    # Save
    output_path = r'c:\Users\Mithun\capstone\Capstone_Project_Complete_Summary.pdf'
    pdf.output(output_path)
    print(f'PDF generated successfully: {output_path}')
    print(f'Total pages: {pdf.page_no()}')

if __name__ == '__main__':
    main()
