# Ghidra Jython script: get_cfg_stats.py
# Extracts CFG statistics and P-code operation counts from analyzed binary
#@category Analysis

from ghidra.program.model.block import BasicBlockModel

# Get current program and managers
prog = getCurrentProgram()
fm = prog.getFunctionManager()
bm = BasicBlockModel(prog)
listing = prog.getListing()

# Initialize counters
num_functions = fm.getFunctionCount()
num_blocks = 0
total_pcode_ops = 0

# Iterate through all functions
func_iter = fm.getFunctions(True)  # True = forward iteration

for func in func_iter:
    # Get blocks within the function's body
    func_body = func.getBody()
    block_iter = bm.getCodeBlocksContaining(func_body, monitor)
    
    # Process each block in this function
    while block_iter.hasNext():
        block = block_iter.next()
        num_blocks += 1
        
        # Get instructions in this block
        instr_iter = listing.getInstructions(block, True)
        
        # Count P-code operations for each instruction
        while instr_iter.hasNext():
            instruction = instr_iter.next()
            
            # Get P-code operations for this instruction
            pcode_ops = instruction.getPcode()
            if pcode_ops is not None:
                total_pcode_ops += len(pcode_ops)

# Print parseable statistics
print("GHIDRA_STATS:Functions={}".format(num_functions))
print("GHIDRA_STATS:BasicBlocks={}".format(num_blocks))
print("GHIDRA_STATS:TotalPcodeOps={}".format(total_pcode_ops))
