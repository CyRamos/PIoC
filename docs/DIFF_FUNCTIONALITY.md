# CTI Platform - Diff Functionality

## Overview

The Diff Functionality is a powerful feature that allows threat intelligence analysts to understand exactly what's new versus what already exists in their database when uploading indicator files. This helps optimize workflows and focus on truly new threats.

## Features

### 1. Intelligent Diff Analysis
- **New Indicators**: Shows indicators that don't exist in the database
- **Existing Indicators**: Shows indicators already in the database with their history
- **Duplicates**: Identifies duplicates within the same file
- **Invalid Indicators**: Shows indicators that couldn't be processed

### 2. Detailed Processing Results
When you upload a file, you'll see:
- **Diff Summary**: Quick metrics showing counts for each category
- **Tabbed Views**: Detailed breakdown by category
- **Source Information**: Track which file/source each indicator came from
- **Timestamps**: When indicators were first and last seen

### 3. Export Capabilities
- **Export New Only**: Export only the new indicators from a file
- **Export by Source**: Filter and export by specific sources
- **Multiple Formats**: CSV and JSON export options
- **Timestamped Files**: All exports include timestamps for tracking

### 4. Source-Based Analysis
- **Source Filtering**: Analyze indicators by source file
- **Date Filtering**: Filter new indicators by date added
- **Bulk Export**: Export multiple sources at once
- **Historical Tracking**: See which sources contributed which indicators

## How to Use

### File Upload with Diff Analysis

1. **Navigate to File Upload**: Go to the "File Upload" page
2. **Upload Files**: Choose your CSV, JSON, TXT, or XML files
3. **View Results**: After processing, see the detailed diff analysis
4. **Export New Data**: Use the export buttons to save only new indicators

### Dedicated Diff Analysis Page

1. **Navigate to Diff Analysis**: Go to the "Diff Analysis" page
2. **Select Sources**: Choose which sources you want to analyze
3. **Set Filters**: Optionally filter by date for "new" indicators
4. **Analyze**: Click "Analyze Selected Sources" to see results
5. **Export**: Export filtered results by source or all together

## File Format Requirements

The diff functionality works with various file formats:

### CSV Format
```csv
indicator_type,value,confidence,source
ip,192.168.1.100,high,malware_sample
domain,evil-site[.]com,critical,phishing_campaign
url,hxxp://malicious[.]example/payload,high,malware_distribution
hash,d41d8cd98f00b204e9800998ecf8427e,medium,file_analysis
email,admin@malicious[.]domain,high,phishing_attempt
```

### JSON Format
```json
{
  "indicators": [
    {
      "type": "ip",
      "value": "192.168.1.100",
      "confidence": "high"
    }
  ]
}
```

### Text Format
```
192.168.1.100
evil-site.com
http://malicious.example/payload
d41d8cd98f00b204e9800998ecf8427e
admin@malicious.domain
```

## Understanding Results

### New Indicators
- **Green Badge**: ✅ Shows count of new indicators
- **Details**: Original value, normalized value, type, source
- **Action**: These will be added to your database
- **Export**: Can export only these new indicators

### Existing Indicators  
- **Blue Badge**: 📋 Shows count of existing indicators
- **Details**: When first/last seen, original source, confidence score
- **Action**: Only the "last seen" timestamp is updated
- **Context**: Helps understand indicator overlap between sources

### Duplicates
- **Yellow Badge**: 🔄 Shows count of duplicates within the file
- **Details**: Shows the duplicate values and why they're duplicates
- **Action**: Only one instance is processed
- **Quality Control**: Helps identify data quality issues

### Invalid Indicators
- **Red Badge**: ❌ Shows count of invalid indicators
- **Details**: Shows what couldn't be processed and why
- **Action**: These are skipped during processing
- **Data Cleaning**: Helps identify and fix data format issues

## Export Options

### Individual File Exports
- **Export New Only (CSV)**: Only new indicators in CSV format
- **Export New Only (JSON)**: Only new indicators in JSON format  
- **Export All (CSV)**: Both new and existing indicators

### Source-Based Exports
- **By Source**: Export indicators from specific sources
- **Date Filtered**: Export only indicators added after a specific date
- **Bulk Export**: Export multiple sources simultaneously

### Export File Naming
Files are automatically named with timestamps:
- `new_indicators_filename_YYYYMMDD_HHMMSS.csv`
- `source_sourcename_YYYYMMDD_HHMMSS.json`
- `selected_sources_YYYYMMDD_HHMMSS.csv`

## Sample Workflow

1. **Initial Upload**: Upload `threat_feed_1.csv`
   - Result: 100 new indicators, 0 existing
   - Export: Save new indicators for sharing

2. **Second Upload**: Upload `threat_feed_2.csv`  
   - Result: 25 new indicators, 75 existing
   - Analysis: 75% overlap with previous data
   - Export: Only the 25 new indicators

3. **Source Analysis**: Use Diff Analysis page
   - Select: Both threat feeds
   - Filter: Only new indicators from last week
   - Export: Combined new threats for weekly report

## Benefits

### For Analysts
- **Focus on New Threats**: Don't waste time on known indicators
- **Quality Control**: Identify duplicates and invalid data
- **Source Tracking**: Understand which feeds provide unique value
- **Efficient Workflows**: Export only what you need

### For Teams
- **Collaboration**: Share only new findings with team members
- **Reporting**: Generate reports with new threats discovered
- **Integration**: Export data for use in other security tools
- **Metrics**: Track feed effectiveness and overlap

### For Operations
- **Storage Optimization**: Avoid storing duplicate indicators
- **Performance**: Faster processing by skipping known indicators
- **Data Quality**: Identify and fix data source issues
- **Audit Trail**: Track which sources contributed which indicators

## Technical Details

### Processing Logic
1. File is parsed and indicators extracted
2. Each indicator is classified and normalized
3. Database lookup checks for existing indicators
4. Results are categorized (new/existing/duplicate/invalid)
5. Only new indicators are stored in database
6. Detailed results are returned for analysis

### Normalization
All indicators are normalized before comparison:
- **URLs**: Defanged URLs are converted to normal format
- **IPs**: Defanged IPs are converted to standard format
- **Domains**: Defanged domains are normalized
- **Hashes**: Converted to lowercase
- **Emails**: Converted to lowercase

### Export Features
- **CSV Export**: Standard comma-separated format
- **JSON Export**: Structured JSON with metadata
- **Automatic Timestamps**: All exports include creation time
- **Preview**: Shows preview of export data when < 10 items

## Best Practices

1. **Regular Analysis**: Use diff analysis weekly to track new threats
2. **Source Management**: Name your sources clearly for easy filtering
3. **Export Strategy**: Export new indicators for sharing with team
4. **Data Quality**: Review invalid indicators to improve data sources
5. **Historical Analysis**: Use date filtering to track threat trends

## Troubleshooting

### No New Indicators Found
- Check if indicators already exist in database
- Verify indicator format is correct
- Review invalid indicators for formatting issues

### Export Fails
- Check if export directory exists and is writable
- Verify you have sufficient disk space
- Check file permissions

### Large File Processing
- Files with >10,000 indicators may take longer
- Consider splitting large files for better performance
- Monitor system resources during processing

## API Integration

The diff functionality is also available via API endpoints:
- `POST /api/process-file` - Process file with diff analysis
- `GET /api/indicators/by-source` - Get indicators by source
- `POST /api/export/csv` - Export indicators to CSV
- `POST /api/export/json` - Export indicators to JSON

For API documentation, visit `/docs` when running the application. 