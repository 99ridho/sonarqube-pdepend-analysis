#!/usr/bin/env python3
"""
PDépend Analyzer & Visualizer
For Research Paper Sections 5.1 (Descriptive Statistics) and 5.2 (Complexity Analysis)
Input: summary.xml from PDépend
"""

import pandas as pd
import numpy as np
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Set style for publication-quality figures
plt.style.use('seaborn-v0_8-paper')
sns.set_palette("husl")

class PdependAnalyzer:
    """Analyze and visualize PDépend metrics"""
    
    def __init__(self, summary_xml_path: str, output_dir: str = './output'):
        self.summary_xml = summary_xml_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        self.files_df = None
        self.classes_df = None
        self.methods_df = None
        
    def parse_pdepend_xml(self):
        """Parse PDépend summary.xml"""
        print("📊 Parsing PDépend XML...")
        
        try:
            tree = ET.parse(self.summary_xml)
            root = tree.getroot()
        except Exception as e:
            print(f"❌ Error parsing XML: {e}")
            return
        
        # Parse files
        files_data = []
        for file_elem in root.findall('.//file'):
            files_data.append({
                'file': file_elem.get('name'),
                'loc': int(file_elem.get('loc', 0)),
                'ncloc': int(file_elem.get('ncloc', 0)),
                'lloc': int(file_elem.get('lloc', 0)),
                'cloc': int(file_elem.get('cloc', 0)),
            })
        
        self.files_df = pd.DataFrame(files_data)
        
        # Parse classes
        classes_data = []
        methods_data = []
        
        for package in root.findall('.//package'):
            if package.get('name') != '+global':
                continue

            for class_elem in package.findall('.//class'):
                file_elem = class_elem.find('file')
                filename = file_elem.get('name') if file_elem is not None else 'unknown'

                if not any(value in filename for value in ["application/models", "application/controllers"]):
                    continue
                
                classes_data.append({
                    'file': filename,
                    'class': class_elem.get('name'),
                    'ccn': int(class_elem.get('ccn', 0)),
                    'ccn2': int(class_elem.get('ccn2', 0)),
                    'wmc': int(class_elem.get('wmc', 0)),
                    'nom': int(class_elem.get('nom', 0)),
                    'noc': int(class_elem.get('noc', 0)),
                    'ca': int(class_elem.get('ca', 0)),
                    'ce': int(class_elem.get('ce', 0)),
                    'cbo': int(class_elem.get('cbo', 0)),
                    'dit': int(class_elem.get('dit', 0)),
                })
                
                # Parse methods
                for method_elem in class_elem.findall('.//method'):
                    methods_data.append({
                        'file': filename,
                        'class': class_elem.get('name'),
                        'method': method_elem.get('name'),
                        'ccn': int(method_elem.get('ccn', 0)),
                        'loc': int(method_elem.get('loc', 0)),
                        'ncloc': int(method_elem.get('nloc', 0)),
                        'npath': int(method_elem.get('npath', 0)),
                    })
        
        self.classes_df = pd.DataFrame(classes_data)
        self.methods_df = pd.DataFrame(methods_data)
        
        print(f"  ✓ Parsed {len(self.files_df)} files")
        print(f"  ✓ Parsed {len(self.classes_df)} classes")
        print(f"  ✓ Parsed {len(self.methods_df)} methods")
    
    def generate_section_5_1_descriptive_stats(self):
        """Generate descriptive statistics for Section 5.1"""
        print("\n📈 Generating Section 5.1: Descriptive Statistics...")
        
        # Calculate aggregate metrics
        stats = {
            'Total Files': len(self.files_df),
            'Total Classes': len(self.classes_df),
            'Total Methods': len(self.methods_df),
            'Total LOC': self.files_df['loc'].sum(),
            'Total NCLOC': self.files_df['ncloc'].sum(),
            'Total LLOC': self.files_df['lloc'].sum(),
            'Total Comment Lines': self.files_df['cloc'].sum(),
            'Avg NCLOC per File': round(self.files_df['ncloc'].mean(), 1),
            'Avg Methods per Class': round(self.classes_df['nom'].mean(), 1),
            'Avg WMC per Class': round(self.classes_df['wmc'].mean(), 1),
            'Max Depth of Inheritance': self.classes_df['dit'].max(),
            'Avg CCN per Method': round(self.methods_df['ccn'].mean(), 1),
        }
        
        # Save to CSV
        stats_df = pd.DataFrame([stats]).T
        stats_df.columns = ['Value']
        stats_path = self.output_dir / 'section_5_1_descriptive_statistics.csv'
        stats_df.to_csv(stats_path)
        print(f"  ✓ Saved: {stats_path}")
        
        # Create summary table
        print("\n" + "="*60)
        print("SECTION 5.1: DESCRIPTIVE STATISTICS OVERVIEW")
        print("="*60)
        for metric, value in stats.items():
            print(f"  {metric:30} : {value}")
        print("="*60)
        
        return stats
    
    def generate_section_5_2_complexity_analysis(self):
        """Generate complexity analysis for Section 5.2"""
        print("\n📈 Generating Section 5.2: Complexity Analysis...")
        
        # File-level complexity distribution
        file_complexity = self.files_df[['file', 'ncloc', 'lloc']].drop_duplicates(subset=['file'], keep='first')
        
        # Class-level complexity (aggregate by file)
        class_metrics = self.classes_df.groupby('file').agg({
            'wmc': 'sum',
            'nom': 'sum',
            'cbo': 'max',
            'ca': 'max',
            'ce': 'max'
        }).reset_index()

        # Merge file and class metrics (inner join to only include files with class data)
        complexity_df = pd.merge(file_complexity, class_metrics, on='file', how='inner')

        # Add method complexity (use method-level CCN as the primary CCN metric)
        method_stats = self.methods_df.groupby('file').agg({
            'ccn': ['sum']
        }).reset_index()
        method_stats.columns = ['file', 'ccn']

        complexity_df = pd.merge(complexity_df, method_stats, on='file', how='inner')
        
        # Sort by WMC
        complexity_df = complexity_df.sort_values('wmc', ascending=False)
        
        # Save full complexity data
        complexity_path = self.output_dir / 'section_5_2_complexity_data.csv'
        complexity_df.to_csv(complexity_path, index=False)
        print(f"  ✓ Saved: {complexity_path}")

        # Generate distribution statistics
        distribution = {
            'NCLOC': self.describe_distribution(complexity_df['ncloc']),
            'WMC': self.describe_distribution(complexity_df['wmc']),
            'CCN': self.describe_distribution(complexity_df['ccn']),
            'CBO': self.describe_distribution(complexity_df['cbo']),
        }
        
        dist_df = pd.DataFrame(distribution).T
        dist_path = self.output_dir / 'section_5_2_complexity_distribution.csv'
        dist_df.to_csv(dist_path)
        print(f"  ✓ Saved: {dist_path}")
        
        # Top 10 complex files
        top10 = complexity_df.head(10)[['file', 'ncloc', 'lloc', 'wmc', 'nom', 'cbo']]
        top10_path = self.output_dir / 'section_5_2_top10_complex_files.csv'
        top10.to_csv(top10_path, index=False)
        print(f"  ✓ Saved: {top10_path}")
        
        # Methods with high complexity
        complex_methods = self.methods_df[self.methods_df['ccn'] > 30].sort_values('ccn', ascending=False)
        complex_methods_path = self.output_dir / 'section_5_2_complex_methods_ccn30.csv'
        complex_methods.to_csv(complex_methods_path, index=False)
        print(f"  ✓ Saved: {complex_methods_path}")
        
        return complexity_df
    
    def describe_distribution(self, series):
        """Calculate distribution statistics"""
        return {
            'Min': series.min(),
            'Q1': series.quantile(0.25),
            'Median': series.median(),
            'Q3': series.quantile(0.75),
            'Max': series.max(),
            'Mean': series.mean(),
            'Std': series.std()
        }
    
    def create_visualizations(self, complexity_df):
        """Create publication-quality visualizations"""
        print("\n🎨 Creating visualizations...")
        
        # Figure 1: Complexity Distribution (Box plots)
        self.viz_complexity_distribution(complexity_df)
        
        # Figure 2: Top 10 Complex Files (Bar chart)
        self.viz_top10_complex_files(complexity_df)
        
        # Figure 3: Method Complexity Distribution (Histogram)
        self.viz_method_complexity_histogram()
        
        # Figure 4: WMC vs NCLOC (Scatter)
        self.viz_wmc_vs_ncloc(complexity_df)
        
        print("  ✓ All visualizations created")
    
    def viz_complexity_distribution(self, df):
        """Visualization: Complexity metrics distribution"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        #fig.suptitle('Figure 5.1: Complexity Metrics Distribution', fontsize=16, fontweight='bold')
        
        metrics = [
            ('ncloc', 'NCLOC (Lines of Code)', axes[0, 0]),
            ('wmc', 'WMC (Weighted Methods per Class)', axes[0, 1]),
            ('ccn', 'CCN (Cyclomatic Complexity)', axes[1, 0]),
            ('cbo', 'CBO (Coupling Between Objects)', axes[1, 1])
        ]
        
        for col, title, ax in metrics:
            data = df[df[col] > 0][col]
            
            # Box plot
            bp = ax.boxplot([data], vert=True, patch_artist=True,
                           boxprops=dict(facecolor='lightblue', alpha=0.7),
                           medianprops=dict(color='red', linewidth=2))
            
            # Add statistics text
            stats_text = f"Mean: {data.mean():.1f}\nMedian: {data.median():.1f}\nMax: {data.max():.0f}"
            ax.text(0.98, 0.98, stats_text, transform=ax.transAxes,
                   fontsize=9, verticalalignment='top', horizontalalignment='right',
                   bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
            
            ax.set_ylabel(title, fontsize=11)
            ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_1_complexity_distribution.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()
    
    def viz_top10_complex_files(self, df):
        """Visualization: Top 10 complex files"""
        fig, ax = plt.subplots(figsize=(12, 6))
        
        top10 = df.nlargest(10, 'wmc')
        
        # Clean filenames for display
        files = [Path(f).name for f in top10['file']]
        wmc_values = top10['wmc'].values
        
        # Create horizontal bar chart
        y_pos = np.arange(len(files))
        bars = ax.barh(y_pos, wmc_values, color='steelblue', alpha=0.8)
        
        # Add value labels
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2, 
                   f' {int(width)}',
                   ha='left', va='center', fontsize=10, fontweight='bold')
        
        # Add threshold line
        threshold = 100
        ax.axvline(x=threshold, color='red', linestyle='--', linewidth=2, 
                  label=f'Threshold (WMC={threshold})')
        
        ax.set_yticks(y_pos)
        ax.set_yticklabels(files)
        ax.invert_yaxis()
        ax.set_xlabel('Weighted Methods per Class (WMC)', fontsize=12)
        # ax.set_title('Figure 5.2: Top 10 Most Complex Files by WMC', 
        #             fontsize=14, fontweight='bold', pad=20)
        ax.legend(loc='lower right')
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_2_top10_complex_files.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()
    
    def viz_method_complexity_histogram(self):
        """Visualization: Method complexity histogram"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        ccn_values = self.methods_df[self.methods_df['ccn'] > 0]['ccn']
        
        # Create histogram
        n, bins, patches = ax.hist(ccn_values, bins=30, range=(0,60), color='skyblue', 
                                   edgecolor='black', alpha=0.7)
        
        # Color bars by threshold
        for i, patch in enumerate(patches):
            if bins[i] >= 30:
                patch.set_facecolor('red')
                patch.set_alpha(0.8)
            elif bins[i] >= 10:
                patch.set_facecolor('orange')
                patch.set_alpha(0.8)
        
        # Add threshold lines
        ax.axvline(x=10, color='orange', linestyle='--', linewidth=2, 
                  label='CCN=10 (High)')
        ax.axvline(x=30, color='red', linestyle='--', linewidth=2, 
                  label='CCN=30 (Critical)')
        
        # Statistics
        stats_text = (f"Total Methods: {len(ccn_values)}\n"
                     f"Mean CCN: {ccn_values.mean():.1f}\n"
                     f"Median CCN: {ccn_values.median():.1f}\n"
                     f"Methods > 10: {(ccn_values > 10).sum()}\n"
                     f"Methods > 30: {(ccn_values > 30).sum()}")
        ax.text(0.98, 0.86, stats_text, transform=ax.transAxes,
               fontsize=10, verticalalignment='top', horizontalalignment='right',
               bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        ax.set_xlabel('Cyclomatic Complexity (CCN)', fontsize=12)
        ax.set_ylabel('Number of Methods', fontsize=12)
        # ax.set_title('Figure 5.3: Method Complexity Distribution', 
        #             fontsize=14, fontweight='bold', pad=20)
        ax.legend(loc='upper right')
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_3_method_complexity_histogram.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()
    
    def viz_wmc_vs_ncloc(self, df):
        """Visualization: WMC vs NCLOC scatter plot"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Filter out zeros
        data = df[(df['wmc'] > 0) & (df['ncloc'] > 0)]
        
        # Create scatter plot
        scatter = ax.scatter(data['ncloc'], data['wmc'], 
                           s=100, alpha=0.6, c=data['wmc'],
                           cmap='YlOrRd', edgecolors='black', linewidth=0.5)
        
        # Add colorbar
        cbar = plt.colorbar(scatter, ax=ax)
        cbar.set_label('WMC Value', fontsize=10)
        
        # Add trend line
        z = np.polyfit(data['ncloc'], data['wmc'], 1)
        p = np.poly1d(z)
        ax.plot(data['ncloc'], p(data['ncloc']), "r--", 
               linewidth=2, alpha=0.8, label=f'Trend line')
        
        # Annotate top files
        top5 = data.nlargest(5, 'wmc')
        for idx, row in top5.iterrows():
            ax.annotate(Path(row['file']).name, 
                       xy=(row['ncloc'], row['wmc']),
                       xytext=(10, 10), textcoords='offset points',
                       fontsize=8, alpha=0.7,
                       bbox=dict(boxstyle='round,pad=0.3', 
                                facecolor='yellow', alpha=0.5),
                       arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0'))
        
        ax.set_xlabel('NCLOC (Non-Comment Lines of Code)', fontsize=12)
        ax.set_ylabel('WMC (Weighted Methods per Class)', fontsize=12)
        # ax.set_title('Figure 5.4: File Size vs Complexity', 
        #             fontsize=14, fontweight='bold', pad=20)
        ax.legend(loc='upper left')
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_4_wmc_vs_ncloc.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()
    
    def run(self):
        """Run complete analysis"""
        print("="*60)
        print("PDépend ANALYZER & VISUALIZER")
        print("Sections 5.1 (Descriptive Statistics) & 5.2 (Complexity)")
        print("="*60 + "\n")
        
        # Parse XML
        self.parse_pdepend_xml()
        
        # Section 5.1
        self.generate_section_5_1_descriptive_stats()
        
        # Section 5.2
        complexity_df = self.generate_section_5_2_complexity_analysis()
        
        # Create visualizations
        self.create_visualizations(complexity_df)
        
        print("\n" + "="*60)
        print("✅ ANALYSIS COMPLETE")
        print("="*60)
        print(f"\n📁 Output directory: {self.output_dir.absolute()}")
        print("\n📊 Generated files:")
        print("  Data Files:")
        print("    • section_5_1_descriptive_statistics.csv")
        print("    • section_5_2_complexity_data.csv")
        print("    • section_5_2_complexity_distribution.csv")
        print("    • section_5_2_top10_complex_files.csv")
        print("    • section_5_2_complex_methods_ccn30.csv")
        print("\n  Visualizations:")
        print("    • figure_5_1_complexity_distribution.png")
        print("    • figure_5_2_top10_complex_files.png")
        print("    • figure_5_3_method_complexity_histogram.png")
        print("    • figure_5_4_wmc_vs_ncloc.png")


def main():
    import sys
    
    # Configuration
    if len(sys.argv) > 1:
        summary_xml = sys.argv[1]
    else:
        summary_xml = 'pdepend-summary.xml'
    
    output_dir = './output_pdepend'
    
    print(f"Input: {summary_xml}")
    print(f"Output: {output_dir}\n")
    
    # Run analysis
    analyzer = PdependAnalyzer(summary_xml, output_dir)
    analyzer.run()


if __name__ == '__main__':
    main()