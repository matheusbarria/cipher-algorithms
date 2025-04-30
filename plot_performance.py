import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Read the CSV file
df = pd.read_csv('performance_results.csv')

# Create a figure with two subplots (encryption and decryption)
plt.figure(figsize=(15, 10))

# Set style
plt.style.use('ggplot')  # Using ggplot style instead of seaborn
colors = ['#FF4B4B', '#4B4BFF', '#4BFF4B', '#FFB74B']  # Custom color palette

# Encryption subplot
plt.subplot(2, 1, 1)
for idx, algorithm in enumerate(df['Algorithm'].unique()):
    data = df[(df['Algorithm'] == algorithm) & (df['Operation'] == 'Encryption')]
    plt.plot(data['Text Length'], data['Mean (ms)'], 
            marker='o', 
            label=algorithm, 
            linewidth=2,
            color=colors[idx])

plt.title('Encryption Performance Comparison', fontsize=14, pad=20)
plt.xlabel('Text Length (characters)', fontsize=12)
plt.ylabel('Time (milliseconds)', fontsize=12)
plt.legend(title='Algorithm', title_fontsize=12, fontsize=10)
plt.grid(True, linestyle='--', alpha=0.7)

# Decryption subplot
plt.subplot(2, 1, 2)
for idx, algorithm in enumerate(df['Algorithm'].unique()):
    data = df[(df['Algorithm'] == algorithm) & (df['Operation'] == 'Decryption')]
    plt.plot(data['Text Length'], data['Mean (ms)'], 
            marker='o', 
            label=algorithm, 
            linewidth=2,
            color=colors[idx])

plt.title('Decryption Performance Comparison', fontsize=14, pad=20)
plt.xlabel('Text Length (characters)', fontsize=12)
plt.ylabel('Time (milliseconds)', fontsize=12)
plt.legend(title='Algorithm', title_fontsize=12, fontsize=10)
plt.grid(True, linestyle='--', alpha=0.7)

# Adjust layout and save
plt.tight_layout()
plt.savefig('performance_comparison.png', dpi=300, bbox_inches='tight')
plt.close()

# Create a bar plot for comparison at specific text lengths
plt.figure(figsize=(15, 8))

# Select specific text lengths for comparison (e.g., 1000 characters)
text_length = 5000
comparison_data = df[df['Text Length'] == text_length]

# Create grouped bar plot
bar_width = 0.35
encryption_data = comparison_data[comparison_data['Operation'] == 'Encryption']
decryption_data = comparison_data[comparison_data['Operation'] == 'Decryption']

x = range(len(encryption_data['Algorithm']))
plt.bar([i - bar_width/2 for i in x], encryption_data['Mean (ms)'], 
        bar_width, label='Encryption', alpha=0.8, color='#FF4B4B')
plt.bar([i + bar_width/2 for i in x], decryption_data['Mean (ms)'], 
        bar_width, label='Decryption', alpha=0.8, color='#4B4BFF')

plt.title(f'Algorithm Performance Comparison at {text_length} Characters', fontsize=14, pad=20)
plt.xlabel('Algorithm', fontsize=12)
plt.ylabel('Time (milliseconds)', fontsize=12)
plt.xticks(x, encryption_data['Algorithm'], rotation=45)
plt.legend()
plt.grid(True, linestyle='--', alpha=0.7)

plt.tight_layout()
plt.savefig('performance_comparison_bars.png', dpi=300, bbox_inches='tight')
plt.close()