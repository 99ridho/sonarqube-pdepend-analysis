#!/usr/bin/env python3
"""
Correlation Analysis Script

This script calculates Pearson correlation coefficients between:
- PDépend complexity metrics
- SonarQube quality issues

Generates:
- Full correlation matrix with p-values
- Summary of significant correlations
- Heatmap visualization
"""

import pandas as pd
import numpy as np
from pathlib import Path
from scipy.stats import pearsonr
import matplotlib.pyplot as plt
import seaborn as sns
import warnings

warnings.filterwarnings('ignore')


class CorrelationAnalyzer:
    """Analyzes correlations between code complexity and quality issues."""

    def __init__(self, pdepend_csv, sonarqube_csv, output_dir='output_correlation'):
        """
        Initialize the analyzer.

        Args:
            pdepend_csv: Path to section_5_2_complexity_data.csv
            sonarqube_csv: Path to section_5_3_file_issues.csv
            output_dir: Directory for output files
        """
        self.pdepend_csv = pdepend_csv
        self.sonarqube_csv = sonarqube_csv
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Data storage
        self.merged_df = None
        self.correlation_matrix = None
        self.pvalue_matrix = None

    def load_and_merge_data(self):
        """Load both CSV files and merge on file paths."""
        print("Loading data files...")

        # Load CSVs
        pdepend_df = pd.read_csv(self.pdepend_csv)
        sonarqube_df = pd.read_csv(self.sonarqube_csv)

        print(f"PDépend data: {len(pdepend_df)} files")
        print(f"SonarQube data: {len(sonarqube_df)} files")

        # Normalize file paths to just filenames for matching
        pdepend_df['filename'] = pdepend_df['file'].apply(lambda x: Path(x).name)
        sonarqube_df['filename'] = sonarqube_df['file'].apply(lambda x: Path(x).name)

        # Merge on filename
        self.merged_df = pd.merge(
            pdepend_df,
            sonarqube_df,
            on='filename',
            how='inner',
            suffixes=('_pdepend', '_sonarqube')
        )

        print(f"Merged data: {len(self.merged_df)} files")

        if len(self.merged_df) == 0:
            raise ValueError("No matching files found between datasets!")

        return self.merged_df

    def calculate_correlations(self):
        """Calculate Pearson correlations between complexity metrics and issues."""
        print("\nCalculating Pearson correlations...")

        # Define complexity metrics from PDépend
        complexity_metrics = [
            'ncloc',           # Non-comment lines of code
            'lloc',            # Logical lines of code
            'wmc',             # Weighted Method Count
            'nom',             # Number of Methods
            'cbo',             # Coupling Between Objects
            'ca',              # Afferent Coupling
            'ce',              # Efferent Coupling
            'ccn'              # Total cyclomatic complexity
        ]

        # Define issue metrics from SonarQube
        issue_metrics = [
            # By quality aspect
            'total_security',
            'total_reliability',
            'total_maintainability',
            # 'total_issues',
            # # By severity (all quality aspects combined)
            # 'security_blocker',
            # 'security_high',
            # 'security_medium',
            # 'security_low',
            # 'reliability_blocker',
            # 'reliability_high',
            # 'reliability_medium',
            # 'reliability_low',
            # 'maintainability_blocker',
            # 'maintainability_high',
            # 'maintainability_medium',
            # 'maintainability_low'
        ]

        # Initialize matrices
        n_complexity = len(complexity_metrics)
        n_issues = len(issue_metrics)

        correlation_values = np.zeros((n_complexity, n_issues))
        pvalue_values = np.zeros((n_complexity, n_issues))

        # Calculate correlations
        for i, complexity_metric in enumerate(complexity_metrics):
            for j, issue_metric in enumerate(issue_metrics):
                if complexity_metric in self.merged_df.columns and issue_metric in self.merged_df.columns:
                    # Remove NaN values
                    mask = ~(self.merged_df[complexity_metric].isna() |
                            self.merged_df[issue_metric].isna())

                    x = self.merged_df.loc[mask, complexity_metric]
                    y = self.merged_df.loc[mask, issue_metric]

                    if len(x) > 2:  # Need at least 3 points for correlation
                        r, p = pearsonr(x, y)
                        correlation_values[i, j] = r
                        pvalue_values[i, j] = p
                    else:
                        correlation_values[i, j] = np.nan
                        pvalue_values[i, j] = np.nan
                else:
                    correlation_values[i, j] = np.nan
                    pvalue_values[i, j] = np.nan

        # Create DataFrames
        self.correlation_matrix = pd.DataFrame(
            correlation_values,
            index=complexity_metrics,
            columns=issue_metrics
        )

        self.pvalue_matrix = pd.DataFrame(
            pvalue_values,
            index=complexity_metrics,
            columns=issue_metrics
        )

        print(f"Calculated {n_complexity} x {n_issues} correlations")

        return self.correlation_matrix, self.pvalue_matrix

    def save_correlation_results(self):
        """Save correlation matrices to CSV files."""
        print("\nSaving correlation results...")

        # Save full correlation matrix
        corr_output = self.output_dir / 'correlation_matrix.csv'
        self.correlation_matrix.to_csv(corr_output)
        print(f"Saved: {corr_output}")

        # Save p-value matrix
        pvalue_output = self.output_dir / 'pvalue_matrix.csv'
        self.pvalue_matrix.to_csv(pvalue_output)
        print(f"Saved: {pvalue_output}")

        # Create summary of significant correlations
        significant_corrs = []

        for complexity_metric in self.correlation_matrix.index:
            for issue_metric in self.correlation_matrix.columns:
                r = self.correlation_matrix.loc[complexity_metric, issue_metric]
                p = self.pvalue_matrix.loc[complexity_metric, issue_metric]

                if not np.isnan(r) and not np.isnan(p) and p < 0.05:
                    significant_corrs.append({
                        'complexity_metric': complexity_metric,
                        'issue_metric': issue_metric,
                        'pearson_r': r,
                        'p_value': p,
                        'significance': '***' if p < 0.001 else '**' if p < 0.01 else '*'
                    })

        # Sort by absolute correlation value
        significant_df = pd.DataFrame(significant_corrs)
        if len(significant_df) > 0:
            significant_df['abs_r'] = significant_df['pearson_r'].abs()
            significant_df = significant_df.sort_values('abs_r', ascending=False)
            significant_df = significant_df.drop('abs_r', axis=1)

        sig_output = self.output_dir / 'significant_correlations.csv'
        significant_df.to_csv(sig_output, index=False)
        print(f"Saved: {sig_output} ({len(significant_df)} significant correlations)")

        return significant_df

    def create_heatmap_visualization(self):
        """Create heatmap visualization of correlation matrix."""
        print("\nCreating correlation heatmap...")

        plt.style.use('seaborn-v0_8-paper')

        # Create figure with larger size for readability
        fig, ax = plt.subplots(figsize=(14, 10))

        # Create mask for non-significant correlations
        #mask = self.pvalue_matrix >= 0.05

        # Create heatmap
        sns.heatmap(
            self.correlation_matrix,
            annot=True,
            fmt='.2f',
            cmap='RdBu_r',
            center=0,
            vmin=-1,
            vmax=1,
            square=False,
            linewidths=0.5,
            cbar_kws={'label': 'Pearson Correlation (r)'},
            ax=ax,
            #mask=mask,  # Gray out non-significant correlations
            annot_kws={'size': 8}
        )

        # Customize labels
        ax.set_xlabel('SonarQube Quality Issues', fontsize=12, fontweight='bold')
        ax.set_ylabel('PDépend Complexity Metrics', fontsize=12, fontweight='bold')
        # ax.set_title('Correlation between Code Complexity and Quality Issues\n(Only p < 0.05 shown)',
        #              fontsize=14, fontweight='bold', pad=20)

        # Rotate x-axis labels for readability
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)

        # Tight layout
        plt.tight_layout()

        # Save figure
        output_file = self.output_dir / 'figure_correlation_heatmap.png'
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"Saved: {output_file}")

        plt.close()

    def generate_summary_statistics(self):
        """Generate summary statistics for the merged dataset."""
        print("\nGenerating summary statistics...")

        summary_stats = {
            'total_files_analyzed': len(self.merged_df),
            'mean_total_issues': self.merged_df['total_issues'].mean(),
            'median_total_issues': self.merged_df['total_issues'].median(),
            'mean_wmc': self.merged_df['wmc'].mean(),
            'median_wmc': self.merged_df['wmc'].median(),
            'mean_ccn': self.merged_df['ccn'].mean(),
            'median_ccn': self.merged_df['ccn'].median()
        }

        summary_df = pd.DataFrame([summary_stats])

        output_file = self.output_dir / 'summary_statistics.csv'
        summary_df.to_csv(output_file, index=False)
        print(f"Saved: {output_file}")

        return summary_df

    def run_analysis(self):
        """Run complete correlation analysis."""
        print("=" * 70)
        print("CORRELATION ANALYSIS: PDépend Complexity vs SonarQube Issues")
        print("=" * 70)

        # Step 1: Load and merge data
        self.load_and_merge_data()

        # Step 2: Calculate correlations
        self.calculate_correlations()

        # Step 3: Save results
        self.save_correlation_results()

        # Step 4: Generate summary statistics
        self.generate_summary_statistics()

        # Step 5: Create visualizations
        self.create_heatmap_visualization()

        print("\n" + "=" * 70)
        print("Analysis complete! Results saved to:", self.output_dir)
        print("=" * 70)


def main():
    """Main entry point."""
    # File paths
    pdepend_csv = 'output_pdepend/section_5_2_complexity_data.csv'
    sonarqube_csv = 'output_sonarqube/section_5_3_file_issues.csv'

    # Create analyzer
    analyzer = CorrelationAnalyzer(pdepend_csv, sonarqube_csv)

    # Run analysis
    analyzer.run_analysis()


if __name__ == '__main__':
    main()
