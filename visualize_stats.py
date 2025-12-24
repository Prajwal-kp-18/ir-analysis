#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import numpy as np

# Read the CSV
df = pd.read_csv('results/malware/summary.csv')

# Calculate statistics
stats = {}
stats['total_samples'] = len(df['Sample_ID'].unique())
stats['total_analyses'] = len(df)

success_by_tool = df.groupby('Tool').apply(
    lambda x: (x['Success_Status'] == 'Success').sum() / len(x) * 100, include_groups=False
).round(2)

successful_df = df[df['Success_Status'] == 'Success']
avg_time_by_tool = successful_df.groupby('Tool')['Time_s'].mean().round(2)
avg_mem_by_tool = successful_df.groupby('Tool')['Mem_MB'].mean().round(2)
avg_blocks_by_tool = successful_df.groupby('Tool')['Block_Count'].mean().round(0)
avg_stmts_by_tool = successful_df.groupby('Tool')['IR_Stmt_Count'].mean().round(0)

arch_dist = df.groupby('Architecture')['Sample_ID'].nunique().sort_values(ascending=False)
failures = df[df['Success_Status'] != 'Success']
failure_by_tool = failures.groupby('Tool').size()

# Create figure with multiple subplots
fig = plt.figure(figsize=(16, 10))
fig.suptitle('Malware Analysis Statistics - 180 Samples, 9 Architectures, 720 Analysis Runs', 
             fontsize=16, fontweight='bold', y=0.98)

gs = GridSpec(3, 3, figure=fig, hspace=0.35, wspace=0.3, 
              left=0.08, right=0.95, top=0.93, bottom=0.06)

# Colors for tools
colors = {'ghidra': '#4CAF50', 'angr': '#2196F3', 'bap': '#FF9800', 'llvm': '#E91E63'}
tools_order = ['ghidra', 'angr', 'bap', 'llvm']

# 1. Success Rates
ax1 = fig.add_subplot(gs[0, 0])
success_data = [success_by_tool[tool] for tool in tools_order]
bars1 = ax1.bar(tools_order, success_data, color=[colors[t] for t in tools_order])
ax1.set_ylabel('Success Rate (%)', fontweight='bold')
ax1.set_title('Success Rates by Tool', fontweight='bold', pad=10)
ax1.set_ylim([0, 105])
ax1.grid(axis='y', alpha=0.3)
for i, (bar, val) in enumerate(zip(bars1, success_data)):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1.5, 
             f'{val:.1f}%', ha='center', fontweight='bold')

# 2. Execution Time
ax2 = fig.add_subplot(gs[0, 1])
time_data = [avg_time_by_tool[tool] for tool in tools_order]
bars2 = ax2.bar(tools_order, time_data, color=[colors[t] for t in tools_order])
ax2.set_ylabel('Time (seconds)', fontweight='bold')
ax2.set_title('Avg Execution Time (Successful Runs)', fontweight='bold', pad=10)
ax2.grid(axis='y', alpha=0.3)
for bar, val in zip(bars2, time_data):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3, 
             f'{val:.1f}s', ha='center', fontsize=9, fontweight='bold')

# 3. Memory Usage
ax3 = fig.add_subplot(gs[0, 2])
mem_data = [avg_mem_by_tool[tool] for tool in tools_order]
bars3 = ax3.bar(tools_order, mem_data, color=[colors[t] for t in tools_order])
ax3.set_ylabel('Memory (MB)', fontweight='bold')
ax3.set_title('Avg Memory Usage (Successful Runs)', fontweight='bold', pad=10)
ax3.grid(axis='y', alpha=0.3)
for bar, val in zip(bars3, mem_data):
    ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 15, 
             f'{val:.0f}MB', ha='center', fontsize=9, fontweight='bold')

# 4. Architecture Distribution
ax4 = fig.add_subplot(gs[1, :2])
arch_names = [name[:20] for name in arch_dist.index[:9]]  # Top 9
arch_counts = arch_dist.values[:9]
bars4 = ax4.barh(arch_names, arch_counts, color='#607D8B')
ax4.set_xlabel('Number of Samples', fontweight='bold')
ax4.set_title('Architecture Distribution (Top 9)', fontweight='bold', pad=10)
ax4.grid(axis='x', alpha=0.3)
ax4.invert_yaxis()
for bar, val in zip(bars4, arch_counts):
    ax4.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2, 
             f'{val}', va='center', fontweight='bold')

# 5. Failure Analysis
ax5 = fig.add_subplot(gs[1, 2])
failure_tools = list(failure_by_tool.index)
failure_counts = list(failure_by_tool.values)
bars5 = ax5.bar(failure_tools, failure_counts, color=[colors.get(t, '#999') for t in failure_tools])
ax5.set_ylabel('Number of Failures', fontweight='bold')
ax5.set_title('Failures by Tool', fontweight='bold', pad=10)
ax5.grid(axis='y', alpha=0.3)
for bar, val in zip(bars5, failure_counts):
    ax5.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
             f'{val}', ha='center', fontweight='bold')

# 6. IR Blocks Generated
ax6 = fig.add_subplot(gs[2, 0])
blocks_data = [avg_blocks_by_tool[tool] for tool in tools_order]
bars6 = ax6.bar(tools_order, blocks_data, color=[colors[t] for t in tools_order])
ax6.set_ylabel('Avg Blocks', fontweight='bold')
ax6.set_title('Avg Basic Blocks Generated', fontweight='bold', pad=10)
ax6.grid(axis='y', alpha=0.3)
for bar, val in zip(bars6, blocks_data):
    ax6.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 200, 
             f'{int(val):,}', ha='center', fontsize=8, fontweight='bold')

# 7. IR Statements Generated
ax7 = fig.add_subplot(gs[2, 1])
stmts_data = [avg_stmts_by_tool[tool] for tool in tools_order]
bars7 = ax7.bar(tools_order, stmts_data, color=[colors[t] for t in tools_order])
ax7.set_ylabel('Avg Statements', fontweight='bold')
ax7.set_title('Avg IR Statements Generated', fontweight='bold', pad=10)
ax7.grid(axis='y', alpha=0.3)
for bar, val in zip(bars7, stmts_data):
    ax7.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1500, 
             f'{int(val):,}', ha='center', fontsize=8, fontweight='bold')

# 8. Summary Statistics Box
ax8 = fig.add_subplot(gs[2, 2])
ax8.axis('off')

summary_text = f"""
KEY FINDINGS

Total Samples: {stats['total_samples']}
Total Runs: {stats['total_analyses']}

Best Success: Ghidra (99.4%)
Fastest: LLVM (5.2s avg)
Most Efficient: BAP (28MB)

Architectures: 9 types
  • ARM: 69 samples
  • MIPS: 28 samples  
  • x86: 23 samples

Total Failures: {len(failures)}
  • LLVM: 84 failures
  • angr: 20 failures
"""

ax8.text(0.1, 0.95, summary_text, transform=ax8.transAxes, 
         fontsize=10, verticalalignment='top', fontfamily='monospace',
         bbox=dict(boxstyle='round', facecolor='#f0f0f0', alpha=0.8))

# Save figure
plt.savefig('results/malware/analysis_visualization.png', dpi=300, bbox_inches='tight')
print('Visualization saved to results/malware/analysis_visualization.png')
