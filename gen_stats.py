#!/usr/bin/env python3
import pandas as pd

df = pd.read_csv('results/malware/summary.csv')

stats = {}
stats['total_samples'] = len(df['Sample_ID'].unique())
stats['total_analyses'] = len(df)

success_by_tool = df.groupby('Tool').apply(
    lambda x: (x['Success_Status'] == 'Success').sum() / len(x) * 100
).round(2)

successful_df = df[df['Success_Status'] == 'Success']
avg_time_by_tool = successful_df.groupby('Tool')['Time_s'].mean().round(2)
avg_mem_by_tool = successful_df.groupby('Tool')['Mem_MB'].mean().round(2)
avg_funcs_by_tool = successful_df.groupby('Tool')['Func_Count'].mean().round(2)
avg_blocks_by_tool = successful_df.groupby('Tool')['Block_Count'].mean().round(2)
avg_stmts_by_tool = successful_df.groupby('Tool')['IR_Stmt_Count'].mean().round(2)

arch_dist = df.groupby('Architecture')['Sample_ID'].nunique().sort_values(ascending=False)
arch_success = df[df['Success_Status'] == 'Success'].groupby('Architecture')['Sample_ID'].nunique()
arch_total = df.groupby('Architecture')['Sample_ID'].nunique()
arch_success_rate = (arch_success / arch_total * 100).round(2)

with open('results/malware/analysis_statistics.txt', 'w') as f:
    f.write('='*80 + '\n')
    f.write('MALWARE ANALYSIS STATISTICS REPORT\n')
    f.write('='*80 + '\n\n')
    
    f.write(f"Total Samples Analyzed: {stats['total_samples']}\n")
    f.write(f"Total Analysis Runs: {stats['total_analyses']}\n\n")
    
    f.write('-'*80 + '\n')
    f.write('SUCCESS RATES BY TOOL\n')
    f.write('-'*80 + '\n')
    for tool, rate in success_by_tool.items():
        f.write(f'{tool:10s}: {rate:6.2f}%\n')
    f.write('\n')
    
    f.write('-'*80 + '\n')
    f.write('AVERAGE EXECUTION TIME (seconds) - Successful Runs Only\n')
    f.write('-'*80 + '\n')
    for tool, time in avg_time_by_tool.items():
        f.write(f'{tool:10s}: {time:8.2f}s\n')
    f.write('\n')
    
    f.write('-'*80 + '\n')
    f.write('AVERAGE MEMORY USAGE (MB) - Successful Runs Only\n')
    f.write('-'*80 + '\n')
    for tool, mem in avg_mem_by_tool.items():
        f.write(f'{tool:10s}: {mem:8.2f} MB\n')
    f.write('\n')
    
    f.write('-'*80 + '\n')
    f.write('AVERAGE IR METRICS - Successful Runs Only\n')
    f.write('-'*80 + '\n')
    f.write(f"{'Tool':<10s} {'Funcs':>10s} {'Blocks':>10s} {'Stmts':>12s}\n")
    f.write('-'*80 + '\n')
    for tool in avg_funcs_by_tool.index:
        f.write(f'{tool:<10s} {avg_funcs_by_tool[tool]:>10.2f} {avg_blocks_by_tool[tool]:>10.2f} {avg_stmts_by_tool[tool]:>12.2f}\n')
    f.write('\n')
    
    f.write('-'*80 + '\n')
    f.write('ARCHITECTURE DISTRIBUTION\n')
    f.write('-'*80 + '\n')
    f.write(f"{'Architecture':<30s} {'Samples':>10s} {'Success Rate':>15s}\n")
    f.write('-'*80 + '\n')
    for arch in arch_dist.index:
        count = arch_dist[arch]
        success_rate = arch_success_rate.get(arch, 0)
        f.write(f'{arch:<30s} {count:>10d} {success_rate:>14.2f}%\n')
    f.write('\n')
    
    failures = df[df['Success_Status'] != 'Success']
    if len(failures) > 0:
        f.write('-'*80 + '\n')
        f.write('FAILURE ANALYSIS\n')
        f.write('-'*80 + '\n')
        failure_by_tool = failures.groupby('Tool').size()
        f.write(f"{'Tool':<10s} {'Failures':>10s}\n")
        f.write('-'*80 + '\n')
        for tool, count in failure_by_tool.items():
            f.write(f'{tool:<10s} {count:>10d}\n')
        f.write('\n')
        
        f.write('Failure Types:\n')
        failure_types = failures['Success_Status'].value_counts()
        for ftype, count in failure_types.items():
            f.write(f'  {ftype}: {count}\n')
    
    f.write('\n' + '='*80 + '\n')
    f.write('END OF REPORT\n')
    f.write('='*80 + '\n')

print('Statistics written to results/malware/analysis_statistics.txt')
