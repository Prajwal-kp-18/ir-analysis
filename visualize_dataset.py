#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import numpy as np

# Read the CSV
df = pd.read_csv('results/malware/summary.csv')

# Calculate dataset statistics
total_samples = len(df['Sample_ID'].unique())
arch_dist = df.groupby('Architecture')['Sample_ID'].nunique().sort_values(ascending=False)
total_architectures = len(arch_dist)

# Create figure
fig = plt.figure(figsize=(14, 8))
fig.suptitle(f'Malware Dataset Diversity - {total_samples} Samples Across {total_architectures} Architectures', 
             fontsize=18, fontweight='bold', y=0.96)

gs = GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3, 
              left=0.08, right=0.95, top=0.90, bottom=0.08)

# Color palette
arch_colors = plt.cm.Set3(np.linspace(0, 1, len(arch_dist)))

# 1. Architecture Distribution - Horizontal Bar Chart
ax1 = fig.add_subplot(gs[:, 0])
arch_names = arch_dist.index
arch_counts = arch_dist.values
bars = ax1.barh(arch_names, arch_counts, color=arch_colors)
ax1.set_xlabel('Number of Samples', fontsize=12, fontweight='bold')
ax1.set_title('Samples by Architecture', fontsize=14, fontweight='bold', pad=15)
ax1.grid(axis='x', alpha=0.3, linestyle='--')
ax1.invert_yaxis()

# Add value labels on bars
for bar, val in zip(bars, arch_counts):
    ax1.text(bar.get_width() + 1.5, bar.get_y() + bar.get_height()/2, 
             f'{val}', va='center', fontweight='bold', fontsize=11)

# 2. Architecture Distribution - Pie Chart
ax2 = fig.add_subplot(gs[0, 1])
wedges, texts, autotexts = ax2.pie(arch_counts, labels=None, autopct='%1.1f%%',
                                     colors=arch_colors, startangle=90,
                                     textprops={'fontweight': 'bold', 'fontsize': 10})
ax2.set_title('Architecture Proportion', fontsize=14, fontweight='bold', pad=15)

# 3. Dataset Summary Statistics
ax3 = fig.add_subplot(gs[1, 1])
ax3.axis('off')

# Calculate additional statistics
top_3_archs = arch_dist.head(3)
top_3_percent = (top_3_archs.sum() / total_samples * 100)

summary_text = f"""
DATASET OVERVIEW

Total Samples: {total_samples}
Total Architectures: {total_architectures}

ARCHITECTURE BREAKDOWN:
"""

for arch, count in arch_dist.items():
    percentage = (count / total_samples * 100)
    summary_text += f"\n  • {arch[:25]:<25s}: {count:>3d} ({percentage:>5.1f}%)"

summary_text += f"""

TOP 3 ARCHITECTURES:
  Combined: {int(top_3_archs.sum())} samples ({top_3_percent:.1f}%)
  
  1. {arch_dist.index[0]}: {arch_dist.values[0]} samples
  2. {arch_dist.index[1]}: {arch_dist.values[1]} samples  
  3. {arch_dist.index[2]}: {arch_dist.values[2]} samples
"""

ax3.text(0.05, 0.95, summary_text, transform=ax3.transAxes, 
         fontsize=10, verticalalignment='top', fontfamily='monospace',
         bbox=dict(boxstyle='round', facecolor='#f8f9fa', alpha=0.9, edgecolor='#dee2e6'))

# Save figure
plt.savefig('results/malware/dataset_diversity.png', dpi=300, bbox_inches='tight')
print('Dataset diversity visualization saved to results/malware/dataset_diversity.png')
