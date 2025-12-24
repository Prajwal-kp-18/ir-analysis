#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Read the CSV
df = pd.read_csv('results/malware/summary.csv')

# Calculate architecture distribution
arch_dist = df.groupby('Architecture')['Sample_ID'].nunique().sort_values(ascending=False)
total_samples = len(df['Sample_ID'].unique())

# Create figure
fig, ax = plt.subplots(figsize=(12, 7))

# Color palette
colors = plt.cm.tab10(np.linspace(0, 1, len(arch_dist)))

# Create horizontal bar chart
bars = ax.barh(arch_dist.index, arch_dist.values, color=colors, edgecolor='black', linewidth=1.2)

# Styling
ax.set_xlabel('Number of Samples', fontsize=14, fontweight='bold')
ax.set_title('Architecture Distribution', fontsize=16, fontweight='bold', pad=20)
ax.grid(axis='x', alpha=0.3, linestyle='--', linewidth=0.7)
ax.invert_yaxis()

# Add value labels on bars with percentage
for bar, val in zip(bars, arch_dist.values):
    percentage = (val / total_samples * 100)
    ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2, 
             f'{val} ({percentage:.1f}%)', va='center', fontweight='bold', fontsize=11)

# Add total samples text
ax.text(0.98, 0.02, f'Total: {total_samples} samples', 
        transform=ax.transAxes, ha='right', fontsize=10,
        bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

plt.tight_layout()
plt.savefig('results/malware/architecture_distribution.png', dpi=300, bbox_inches='tight')
print('Architecture distribution visualization saved to results/malware/architecture_distribution.png')
