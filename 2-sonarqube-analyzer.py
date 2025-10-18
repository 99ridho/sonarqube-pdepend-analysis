#!/usr/bin/env python3
"""
SonarQube Analyzer & Visualizer
For Research Paper Sections 5.3, 5.5, and 5.6
- Section 5.3: Quality Issues
- Section 5.5: Security Hotspots
- Section 5.6: OWASP Top 10 - 2021 Analysis
Input: File paths list + SonarQube API access
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import requests
from pathlib import Path
import time

plt.style.use('seaborn-v0_8-paper')
sns.set_palette("husl")


class SonarQubeAnalyzer:
    """Analyze and visualize SonarQube quality metrics"""
    
    def __init__(self, sonar_host: str, project_key: str, token: str, 
                 file_paths: list = None, output_dir: str = './output'):
        self.sonar_host = sonar_host
        self.project_key = project_key
        self.token = token
        self.file_paths = file_paths or []
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        self.auth = (token, '')
        self.base_url = f"{sonar_host}/api"
        
        self.file_issues_df = None
        self.hotspot_categories_df = None
        self.owasp_top10_df = None
        self.overall_stats = None
    
    def fetch_file_issues(self):
        """Fetch issues for specific files (Section 5.3)"""
        print("📊 Fetching file-level issues from SonarQube...")
        
        if not self.file_paths:
            print("  ℹ️  No specific files provided, fetching all project files...")
            self.file_paths = self._get_all_project_files()
        
        file_data = []
        issues_url = f"{self.base_url}/issues/search"
        
        for idx, filepath in enumerate(self.file_paths):
            if idx % 10 == 0:
                print(f"    Processing {idx+1}/{len(self.file_paths)}...")
            
            # Build component key
            component_key = f"{self.project_key}:{filepath}"
            
            # Initialize counters
            issues = {
                'file': filepath,
                'security_blocker': 0, 'security_high': 0, 'security_medium': 0,
                'security_low': 0, 'security_info': 0,
                'reliability_blocker': 0, 'reliability_high': 0, 'reliability_medium': 0,
                'reliability_low': 0, 'reliability_info': 0,
                'maintainability_blocker': 0, 'maintainability_high': 0, 'maintainability_medium': 0,
                'maintainability_low': 0, 'maintainability_info': 0,
                'security_hotspots': 0
            }
            
            # Fetch issues for this file
            page = 1
            while True:
                try:
                    response = requests.get(issues_url, params={
                        'componentKeys': component_key,
                        'resolved': 'false',
                        'ps': 500,
                        'p': page
                    }, auth=self.auth, timeout=10)
                    
                    if response.status_code != 200:
                        break
                    
                    data = response.json()
                    
                    if 'issues' not in data or len(data['issues']) == 0:
                        break
                    
                    # Count issues by quality and severity
                    for issue in data['issues']:
                        impacts = issue.get('impacts', [])
                        
                        if impacts:
                            for impact in impacts:
                                quality = impact.get('softwareQuality', '').lower()
                                severity = impact.get('severity', '').lower()
                                key = f"{quality}_{severity}"
                                if key in issues:
                                    issues[key] += 1
                        else:
                            # Fallback for Standard mode
                            issue_type = issue.get('type', '').lower()
                            severity = issue.get('severity', 'MEDIUM').lower()
                            
                            quality_map = {
                                'bug': 'reliability',
                                'vulnerability': 'security',
                                'code_smell': 'maintainability'
                            }
                            quality = quality_map.get(issue_type, 'maintainability')
                            
                            severity_map = {
                                'blocker': 'blocker',
                                'critical': 'high',
                                'major': 'medium',
                                'minor': 'low',
                                'info': 'info'
                            }
                            severity = severity_map.get(severity, 'medium')
                            
                            key = f"{quality}_{severity}"
                            if key in issues:
                                issues[key] += 1
                    
                    page += 1
                    if page > 10:
                        break
                        
                except Exception as e:
                    print(f"    ⚠️ Error fetching issues for {filepath}: {e}")
                    break
            
            # Calculate totals
            issues['total_security'] = sum([issues[k] for k in issues if k.startswith('security_') and k != 'security_hotspots'])
            issues['total_reliability'] = sum([issues[k] for k in issues if k.startswith('reliability_')])
            issues['total_maintainability'] = sum([issues[k] for k in issues if k.startswith('maintainability_')])
            issues['total_issues'] = issues['total_security'] + issues['total_reliability'] + issues['total_maintainability']
            
            file_data.append(issues)
            
            # Rate limiting
            if idx % 50 == 0 and idx > 0:
                time.sleep(0.5)
        
        self.file_issues_df = pd.DataFrame(file_data)
        
        # Save results
        output_path = self.output_dir / 'section_5_3_file_issues.csv'
        self.file_issues_df.to_csv(output_path, index=False)
        print(f"  ✓ Saved: {output_path}")
        print(f"  ✓ Processed {len(file_data)} files")
        
        return self.file_issues_df
    
    def _get_all_project_files(self):
        """Get all files in the project"""
        measures_url = f"{self.base_url}/measures/component_tree"
        
        files = []
        page = 1
        
        while True:
            try:
                response = requests.get(measures_url, params={
                    'component': self.project_key,
                    'metricKeys': 'ncloc',
                    'strategy': 'leaves',
                    'ps': 500,
                    'p': page
                }, auth=self.auth, timeout=30)
                
                response.raise_for_status()
                data = response.json()
                
                if 'components' not in data or len(data['components']) == 0:
                    break
                
                for comp in data['components']:
                    if comp['qualifier'] == 'FIL':
                        files.append(comp.get('path', ''))
                
                page += 1
                if page > 20:
                    break
                    
            except Exception as e:
                print(f"  ⚠️ Error fetching files: {e}")
                break
        
        return files
    
    def fetch_hotspot_categories(self):
        """Fetch security hotspot categories (Section 5.5)"""
        print("\n📊 Fetching security hotspots...")

        hotspots_url = f"{self.base_url}/hotspots/search"
        all_hotspots = []
        page = 1
        category_counts = {}

        try:
            while True:
                response = requests.get(hotspots_url, params={
                    'projectKey': self.project_key,
                    'ps': 500,
                    'p': page,
                    'files': ','.join(self.file_paths)
                }, auth=self.auth, timeout=30)

                response.raise_for_status()
                data = response.json()

                hotspots = data.get('hotspots', [])
                if not hotspots:
                    break

                # Aggregate categories
                for hotspot in hotspots:
                    category_code = hotspot.get('securityCategory', 'unknown')
                    category_counts[category_code] = category_counts.get(category_code, 0) + 1

                all_hotspots.extend(hotspots)

                # Check pagination
                paging = data.get('paging', {})
                total_pages = (paging.get('total', 0) + 499) // 500  # Calculate total pages

                print(f"  ✓ Fetched page {page}/{total_pages} ({len(hotspots)} hotspots)")

                if page >= total_pages:
                    break

                page += 1

                # Safety limit
                if page > 100:
                    print("  ⚠️ Reached page limit (100), stopping...")
                    break

            # Build categories list (use API codes as-is)
            categories = []
            for category_code, count in category_counts.items():
                category_name = category_code
                categories.append({
                    'category_code': category_code,
                    'category_name': category_name,
                    'count': count
                })

            self.hotspot_categories_df = pd.DataFrame(categories).sort_values('count', ascending=False)

            # Calculate percentages
            if not self.hotspot_categories_df.empty:
                total = self.hotspot_categories_df['count'].sum()
                self.hotspot_categories_df['percentage'] = (self.hotspot_categories_df['count'] / total * 100).round(1)

            # Save results
            output_path = self.output_dir / 'section_5_5_hotspot_categories.csv'
            self.hotspot_categories_df.to_csv(output_path, index=False)
            print(f"  ✓ Saved: {output_path}")
            print(f"  ✓ Found {len(categories)} hotspot categories")
            print(f"  ✓ Total hotspots: {len(all_hotspots)}")

        except Exception as e:
            print(f"  ❌ Error fetching hotspot categories: {e}")
            self.hotspot_categories_df = pd.DataFrame()

        return self.hotspot_categories_df

    def fetch_owasp_top10(self):
        """Fetch OWASP Top 10 - 2021 Analysis"""
        print("\n📊 Fetching OWASP Top 10 - 2021 analysis...")

        issues_url = f"{self.base_url}/issues/search"

        try:
            # Step 1: Fetch facets to get OWASP categories
            print("  ℹ️  Fetching OWASP Top 10 facets...")
            response = requests.get(issues_url, params={
                'components': self.project_key,
                'ps': 1,
                'facets': 'owaspTop10-2021'
            }, auth=self.auth, timeout=30)

            response.raise_for_status()
            data = response.json()

            # Extract OWASP categories from facets
            owasp_categories = []
            facets = data.get('facets', [])
            for facet in facets:
                if facet.get('property') == 'owaspTop10-2021':
                    for value in facet.get('values', []):
                        owasp_categories.append(value.get('val'))

            if not owasp_categories:
                print("  ⚠️ No OWASP Top 10 - 2021 categories found")
                self.owasp_top10_df = pd.DataFrame()
                return self.owasp_top10_df

            print(f"  ✓ Found {len(owasp_categories)} OWASP categories: {', '.join(owasp_categories)}")

            # Step 2: Fetch issues for all OWASP categories
            print("  ℹ️  Fetching OWASP Top 10 issues...")
            owasp_param = ','.join(owasp_categories)

            all_issues = []
            page = 1

            while True:
                response = requests.get(issues_url, params={
                    'components': self.project_key,
                    's': 'SEVERITY',
                    'ps': 500,
                    'p': page,
                    'facets': 'owaspTop10-2021',
                    'owaspTop10-2021': owasp_param
                }, auth=self.auth, timeout=30)

                response.raise_for_status()
                data = response.json()

                issues = data.get('issues', [])
                if not issues:
                    break

                all_issues.extend(issues)

                # Check pagination
                paging = data.get('paging', {})
                total_pages = (paging.get('total', 0) + 499) // 500

                print(f"  ✓ Fetched page {page}/{total_pages} ({len(issues)} issues)")

                if page >= total_pages:
                    break

                page += 1

                # Safety limit
                if page > 100:
                    print("  ⚠️ Reached page limit (100), stopping...")
                    break

            # Step 3: Aggregate issues by OWASP category
            print("  ℹ️  Aggregating issues by OWASP category...")
            category_data = {}

            # Re-fetch facets with all issues to get accurate counts
            response = requests.get(issues_url, params={
                'components': self.project_key,
                'ps': 1,
                'facets': 'owaspTop10-2021',
                'owaspTop10-2021': owasp_param
            }, auth=self.auth, timeout=30)

            response.raise_for_status()
            data = response.json()

            facets = data.get('facets', [])
            for facet in facets:
                if facet.get('property') == 'owaspTop10-2021':
                    for value in facet.get('values', []):
                        category_code = value.get('val')
                        count = value.get('count', 0)
                        category_data[category_code] = {
                            'category_code': category_code,
                            'category_name': f'A{category_code[1:].upper()}' if category_code.startswith('a') else category_code.upper(),
                            'count': count
                        }

            # Convert to DataFrame
            categories_list = list(category_data.values())
            self.owasp_top10_df = pd.DataFrame(categories_list).sort_values('count', ascending=False)

            # Calculate percentages
            if not self.owasp_top10_df.empty:
                total = self.owasp_top10_df['count'].sum()
                self.owasp_top10_df['percentage'] = (self.owasp_top10_df['count'] / total * 100).round(1)

            # Save results
            output_path = self.output_dir / 'section_5_6_owasp_top10_categories.csv'
            self.owasp_top10_df.to_csv(output_path, index=False)
            print(f"  ✓ Saved: {output_path}")
            print(f"  ✓ Found {len(categories_list)} OWASP Top 10 categories")
            print(f"  ✓ Total issues: {len(all_issues)}")

        except Exception as e:
            print(f"  ❌ Error fetching OWASP Top 10 data: {e}")
            self.owasp_top10_df = pd.DataFrame()

        return self.owasp_top10_df

    def generate_section_5_3_analysis(self):
        """Generate analysis for Section 5.3"""
        print("\n📈 Generating Section 5.3: Quality Issues Analysis...")
        
        if self.file_issues_df is None:
            print("  ❌ No file issues data available")
            return
        
        # Overall summary
        summary = {
            'Total Files Analyzed': len(self.file_issues_df),
            'Total Issues': int(self.file_issues_df['total_issues'].sum()),
            'Total Security Issues': int(self.file_issues_df['total_security'].sum()),
            'Total Reliability Issues': int(self.file_issues_df['total_reliability'].sum()),
            'Total Maintainability Issues': int(self.file_issues_df['total_maintainability'].sum()),
            'Files with Security Issues': int((self.file_issues_df['total_security'] > 0).sum()),
            'Files with Reliability Issues': int((self.file_issues_df['total_reliability'] > 0).sum()),
            'Files with Maintainability Issues': int((self.file_issues_df['total_maintainability'] > 0).sum()),
            'Avg Issues per File': round(self.file_issues_df['total_issues'].mean(), 1),
            'Max Issues in Single File': int(self.file_issues_df['total_issues'].max()),
        }
        
        self.overall_stats = summary
        
        # Save summary
        summary_df = pd.DataFrame([summary]).T
        summary_df.columns = ['Value']
        summary_path = self.output_dir / 'section_5_3_overall_summary.csv'
        summary_df.to_csv(summary_path)
        print(f"  ✓ Saved: {summary_path}")
        
        # Issues by severity
        severity_data = {
            'Blocker': {
                'Security': int(self.file_issues_df['security_blocker'].sum()),
                'Reliability': int(self.file_issues_df['reliability_blocker'].sum()),
                'Maintainability': int(self.file_issues_df['maintainability_blocker'].sum()),
            },
            'High': {
                'Security': int(self.file_issues_df['security_high'].sum()),
                'Reliability': int(self.file_issues_df['reliability_high'].sum()),
                'Maintainability': int(self.file_issues_df['maintainability_high'].sum()),
            },
            'Medium': {
                'Security': int(self.file_issues_df['security_medium'].sum()),
                'Reliability': int(self.file_issues_df['reliability_medium'].sum()),
                'Maintainability': int(self.file_issues_df['maintainability_medium'].sum()),
            },
            'Low': {
                'Security': int(self.file_issues_df['security_low'].sum()),
                'Reliability': int(self.file_issues_df['reliability_low'].sum()),
                'Maintainability': int(self.file_issues_df['maintainability_low'].sum()),
            }
        }
        
        severity_df = pd.DataFrame(severity_data).T
        severity_path = self.output_dir / 'section_5_3_issues_by_severity.csv'
        severity_df.to_csv(severity_path)
        print(f"  ✓ Saved: {severity_path}")
        
        # Top 20 problematic files
        top20 = self.file_issues_df.nlargest(20, 'total_issues')[[
            'file', 'total_security', 'total_reliability', 'total_maintainability', 'total_issues'
        ]]
        top20_path = self.output_dir / 'section_5_3_top20_problematic_files.csv'
        top20.to_csv(top20_path, index=False)
        print(f"  ✓ Saved: {top20_path}")
        
        # Print summary
        print("\n" + "="*60)
        print("SECTION 5.3: QUALITY ISSUES SUMMARY")
        print("="*60)
        for metric, value in summary.items():
            print(f"  {metric:35} : {value}")
        print("="*60)
    
    def create_section_5_3_visualizations(self):
        """Create visualizations for Section 5.3"""
        print("\n🎨 Creating Section 5.3 visualizations...")
        
        # Figure 1: Issues by Quality Aspect (Stacked Bar)
        self.viz_issues_by_quality_severity()
        
        # Figure 2: Top 10 Files by Issues
        self.viz_top10_files_issues()
        
        # Figure 3: Issue Distribution (Pie Chart)
        self.viz_issue_distribution_pie()
        
        print("  ✓ Section 5.3 visualizations created")
    
    def viz_issues_by_quality_severity(self):
        """Visualization: Issues by quality and severity"""
        fig, ax = plt.subplots(figsize=(12, 6))
        
        # Prepare data
        severities = ['Blocker', 'High', 'Medium', 'Low']
        security = [
            self.file_issues_df['security_blocker'].sum(),
            self.file_issues_df['security_high'].sum(),
            self.file_issues_df['security_medium'].sum(),
            self.file_issues_df['security_low'].sum()
        ]
        reliability = [
            self.file_issues_df['reliability_blocker'].sum(),
            self.file_issues_df['reliability_high'].sum(),
            self.file_issues_df['reliability_medium'].sum(),
            self.file_issues_df['reliability_low'].sum()
        ]
        maintainability = [
            self.file_issues_df['maintainability_blocker'].sum(),
            self.file_issues_df['maintainability_high'].sum(),
            self.file_issues_df['maintainability_medium'].sum(),
            self.file_issues_df['maintainability_low'].sum()
        ]
        
        x = np.arange(len(severities))
        width = 0.25
        
        bars1 = ax.bar(x - width, security, width, label='Security', color='#e74c3c')
        bars2 = ax.bar(x, reliability, width, label='Reliability', color='#3498db')
        bars3 = ax.bar(x + width, maintainability, width, label='Maintainability', color='#2ecc71')
        
        # Add value labels on bars
        for bars in [bars1, bars2, bars3]:
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    ax.text(bar.get_x() + bar.get_width()/2., height,
                           f'{int(height)}',
                           ha='center', va='bottom', fontsize=9)
        
        ax.set_xlabel('Severity Level', fontsize=12)
        ax.set_ylabel('Number of Issues', fontsize=12)
        # ax.set_title('Figure 5.5: Issues Distribution by Quality Aspect and Severity',
        #             fontsize=14, fontweight='bold', pad=20)
        ax.set_xticks(x)
        ax.set_xticklabels(severities)
        ax.legend(loc='upper right', fontsize=10)
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_5_issues_by_quality_severity.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()
    
    def viz_top10_files_issues(self):
        """Visualization: Top 10 files by total issues"""
        fig, ax = plt.subplots(figsize=(12, 6))
        
        top10 = self.file_issues_df.nlargest(10, 'total_issues')
        
        # Clean filenames
        files = [Path(f).name for f in top10['file']]
        
        # Stacked bar chart
        security = top10['total_security'].values
        reliability = top10['total_reliability'].values
        maintainability = top10['total_maintainability'].values
        
        y_pos = np.arange(len(files))
        
        bars1 = ax.barh(y_pos, security, label='Security', color='#e74c3c')
        bars2 = ax.barh(y_pos, reliability, left=security, label='Reliability', color='#3498db')
        bars3 = ax.barh(y_pos, maintainability, left=security+reliability, 
                       label='Maintainability', color='#2ecc71')
        
        # Add total labels
        totals = top10['total_issues'].values
        for i, total in enumerate(totals):
            ax.text(total, i, f' {int(total)}', 
                   va='center', fontsize=10, fontweight='bold')
        
        ax.set_yticks(y_pos)
        ax.set_yticklabels(files)
        ax.invert_yaxis()
        ax.set_xlabel('Number of Issues', fontsize=12)
        # ax.set_title('Figure 5.6: Top 10 Files by Total Issues',
        #             fontsize=14, fontweight='bold', pad=20)
        ax.legend(loc='lower right')
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_6_top10_files_issues.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()
    
    def viz_issue_distribution_pie(self):
        """Visualization: Overall issue distribution"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Left: By Quality
        qualities = ['Security', 'Reliability', 'Maintainability']
        quality_counts = [
            self.file_issues_df['total_security'].sum(),
            self.file_issues_df['total_reliability'].sum(),
            self.file_issues_df['total_maintainability'].sum()
        ]
        
        colors1 = ['#e74c3c', '#3498db', '#2ecc71']
        explode1 = (0.05, 0.05, 0.05)
        
        wedges1, texts1, autotexts1 = ax1.pie(quality_counts, explode=explode1, labels=qualities,
                                               colors=colors1, autopct='%1.1f%%',
                                               shadow=True, startangle=90)
        
        for autotext in autotexts1:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(11)
        
        ax1.set_title('By Quality Aspect', fontsize=12, fontweight='bold')
        
        # Right: By Severity
        severities = ['Blocker', 'High', 'Medium', 'Low']
        severity_counts = [
            self.file_issues_df[['security_blocker', 'reliability_blocker', 'maintainability_blocker']].sum().sum(),
            self.file_issues_df[['security_high', 'reliability_high', 'maintainability_high']].sum().sum(),
            self.file_issues_df[['security_medium', 'reliability_medium', 'maintainability_medium']].sum().sum(),
            self.file_issues_df[['security_low', 'reliability_low', 'maintainability_low']].sum().sum()
        ]
        
        colors2 = ['#c0392b', '#e67e22', '#f39c12', '#f1c40f']
        explode2 = (0.1, 0.05, 0, 0)
        
        wedges2, texts2, autotexts2 = ax2.pie(severity_counts, explode=explode2, labels=severities,
                                               colors=colors2, autopct='%1.1f%%',
                                               shadow=True, startangle=90)
        
        for autotext in autotexts2:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(11)
        
        ax2.set_title('By Severity Level', fontsize=12, fontweight='bold')
        
        # fig.suptitle('Figure 5.7: Overall Issue Distribution', 
        #             fontsize=14, fontweight='bold', y=1.02)
        
        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_7_issue_distribution.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()

    def generate_owasp_top10_analysis(self):
        """Generate analysis for OWASP Top 10 - 2021"""
        print("\n📈 Generating OWASP Top 10 - 2021 Analysis...")

        if self.owasp_top10_df is None or self.owasp_top10_df.empty:
            print("  ❌ No OWASP Top 10 data available")
            return

        # Overall summary
        summary = {
            'Total OWASP Categories': len(self.owasp_top10_df),
            'Total Issues': int(self.owasp_top10_df['count'].sum()),
            'Most Common Category': self.owasp_top10_df.iloc[0]['category_name'] if len(self.owasp_top10_df) > 0 else 'N/A',
            'Most Common Category Count': int(self.owasp_top10_df.iloc[0]['count']) if len(self.owasp_top10_df) > 0 else 0,
            'Most Common Category %': float(self.owasp_top10_df.iloc[0]['percentage']) if len(self.owasp_top10_df) > 0 else 0.0,
        }

        # Save summary
        summary_df = pd.DataFrame([summary]).T
        summary_df.columns = ['Value']
        summary_path = self.output_dir / 'section_5_6_owasp_top10_summary.csv'
        summary_df.to_csv(summary_path)
        print(f"  ✓ Saved: {summary_path}")

        # Print summary
        print("\n" + "="*60)
        print("OWASP TOP 10 - 2021 SUMMARY")
        print("="*60)
        for metric, value in summary.items():
            print(f"  {metric:35} : {value}")
        print("="*60)

        # Print top categories
        print("\nTop OWASP Top 10 - 2021 Categories:")
        for idx, row in self.owasp_top10_df.iterrows():
            print(f"  {row['category_name']:10} : {int(row['count']):5} issues ({row['percentage']:5.1f}%)")

    def create_section_5_5_visualizations(self):
        """Create visualizations for Section 5.5 (Hotspots)"""
        print("\n🎨 Creating Section 5.5 visualizations...")
        
        if self.hotspot_categories_df is None or self.hotspot_categories_df.empty:
            print("  ⚠️ No hotspot data available")
            return
        
        self.viz_hotspot_categories()
        
        print("  ✓ Section 5.5 visualizations created")
    
    def viz_hotspot_categories(self):
        """Visualization: Security hotspot categories"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

        # Left: Bar chart
        categories = self.hotspot_categories_df['category_name'].head(10).values
        counts = self.hotspot_categories_df['count'].head(10).values
        
        bars = ax1.barh(range(len(categories)), counts, color='coral', alpha=0.8)
        
        # Add value labels
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax1.text(width, bar.get_y() + bar.get_height()/2,
                    f' {int(width)} ({self.hotspot_categories_df["percentage"].iloc[i]}%)',
                    ha='left', va='center', fontsize=10, fontweight='bold')
        
        ax1.set_yticks(range(len(categories)))
        ax1.set_yticklabels(categories)
        ax1.invert_yaxis()
        ax1.set_xlabel('Number of Hotspots', fontsize=12)
        ax1.set_title('Security Hotspot Identified', fontsize=12, fontweight='bold')
        ax1.grid(True, alpha=0.3, axis='x')
        
        # Right: Pie chart (top 8 + others)
        top8 = self.hotspot_categories_df.head(8)
        others_count = self.hotspot_categories_df['count'].iloc[8:].sum() if len(self.hotspot_categories_df) > 8 else 0

        pie_labels = list(top8['category_name'].values)
        pie_counts = list(top8['count'].values)
        
        if others_count > 0:
            pie_labels.append('Others')
            pie_counts.append(others_count)
        
        colors = plt.cm.Set3(range(len(pie_labels)))
        explode = [0.05] * len(pie_labels)
        explode[0] = 0.1
        
        wedges, texts, autotexts = ax2.pie(pie_counts, explode=explode, labels=pie_labels,
                                            colors=colors, autopct='%1.1f%%',
                                            shadow=True, startangle=90)
        
        for autotext in autotexts:
            autotext.set_color('black')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(10)
        
        ax2.set_title('Distribution by Category', fontsize=12, fontweight='bold')
        
        # fig.suptitle('Figure 5.8: Security Hotspot Categorization',
        #             fontsize=14, fontweight='bold', y=1.00)
        
        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_8_hotspot_categories.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()

    def create_owasp_top10_visualizations(self):
        """Create visualizations for OWASP Top 10 - 2021"""
        print("\n🎨 Creating OWASP Top 10 - 2021 visualizations...")

        if self.owasp_top10_df is None or self.owasp_top10_df.empty:
            print("  ⚠️ No OWASP Top 10 data available")
            return

        self.viz_owasp_top10_distribution()

        print("  ✓ OWASP Top 10 - 2021 visualizations created")

    def viz_owasp_top10_distribution(self):
        """Visualization: OWASP Top 10 - 2021 distribution"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

        # Left: Bar chart (all categories)
        categories = self.owasp_top10_df['category_name'].values
        counts = self.owasp_top10_df['count'].values

        bars = ax1.barh(range(len(categories)), counts, color='#e74c3c', alpha=0.8)

        # Add value labels
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax1.text(width, bar.get_y() + bar.get_height()/2,
                    f' {int(width)} ({self.owasp_top10_df["percentage"].iloc[i]}%)',
                    ha='left', va='center', fontsize=10, fontweight='bold')

        ax1.set_yticks(range(len(categories)))
        ax1.set_yticklabels(categories)
        ax1.invert_yaxis()
        ax1.set_xlabel('Number of Issues', fontsize=12)
        ax1.set_title('OWASP Top 10 - 2021 Categories', fontsize=12, fontweight='bold')
        ax1.grid(True, alpha=0.3, axis='x')

        # Right: Pie chart (top 8 + others)
        top8 = self.owasp_top10_df.head(8)
        others_count = self.owasp_top10_df['count'].iloc[8:].sum() if len(self.owasp_top10_df) > 8 else 0

        pie_labels = list(top8['category_name'].values)
        pie_counts = list(top8['count'].values)

        if others_count > 0:
            pie_labels.append('Others')
            pie_counts.append(others_count)

        colors = ['#e74c3c', '#e67e22', '#f39c12', '#f1c40f', '#2ecc71', '#3498db', '#9b59b6', '#e91e63', '#95a5a6']
        explode = [0.05] * len(pie_labels)
        if len(explode) > 0:
            explode[0] = 0.1

        wedges, texts, autotexts = ax2.pie(pie_counts, explode=explode, labels=pie_labels,
                                            colors=colors[:len(pie_labels)], autopct='%1.1f%%',
                                            shadow=True, startangle=90)

        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(10)

        ax2.set_title('Distribution by Category', fontsize=12, fontweight='bold')

        plt.tight_layout()
        save_path = self.output_dir / 'figure_5_9_owasp_top10_distribution.png'
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"  ✓ Saved: {save_path}")
        plt.close()

    def run(self):
        """Run complete analysis"""
        print("="*60)
        print("SONARQUBE ANALYZER & VISUALIZER")
        print("Sections 5.3, 5.5, 5.6 (Quality Issues, Hotspots, OWASP)")
        print("="*60 + "\n")
        
        # Fetch data
        self.fetch_file_issues()
        self.fetch_hotspot_categories()
        self.fetch_owasp_top10()

        # Section 5.3 Analysis
        self.generate_section_5_3_analysis()
        self.create_section_5_3_visualizations()

        # Section 5.5 Analysis
        self.create_section_5_5_visualizations()

        # OWASP Top 10 - 2021 Analysis
        self.generate_owasp_top10_analysis()
        self.create_owasp_top10_visualizations()
        
        print("\n" + "="*60)
        print("✅ ANALYSIS COMPLETE")
        print("="*60)
        print(f"\n📁 Output directory: {self.output_dir.absolute()}")
        print("\n📊 Generated files:")
        print("  Data Files:")
        print("    • section_5_3_file_issues.csv")
        print("    • section_5_3_overall_summary.csv")
        print("    • section_5_3_issues_by_severity.csv")
        print("    • section_5_3_top20_problematic_files.csv")
        print("    • section_5_5_hotspot_categories.csv")
        print("    • section_5_6_owasp_top10_categories.csv")
        print("    • section_5_6_owasp_top10_summary.csv")
        print("\n  Visualizations:")
        print("    • figure_5_5_issues_by_quality_severity.png")
        print("    • figure_5_6_top10_files_issues.png")
        print("    • figure_5_7_issue_distribution.png")
        print("    • figure_5_8_hotspot_categories.png")
        print("    • figure_5_9_owasp_top10_distribution.png")


def main():
    import sys
    import json

    with open('./config.json', 'r') as file:
        data = json.load(file)
    
    # Configuration
    config = {
        'sonar_host': data['sonar_host'],
        'project_key': data['sonar_project_key'],
        'token': data['sonar_token'],
        'output_dir': './output_sonarqube'
    }
    
    # Optional: provide specific file paths
    file_paths = data['file_paths_to_analyze']
    
    print(f"SonarQube Host: {config['sonar_host']}")
    print(f"Project Key: {config['project_key']}")
    print(f"Output: {config['output_dir']}")
    print(f"File paths: {len(file_paths) if file_paths else 'All project files'}\n")
    
    # Run analysis
    analyzer = SonarQubeAnalyzer(
        sonar_host=config['sonar_host'],
        project_key=config['project_key'],
        token=config['token'],
        file_paths=file_paths,  # Leave as [] to scan all files
        output_dir=config['output_dir']
    )
    analyzer.run()


if __name__ == '__main__':
    main()