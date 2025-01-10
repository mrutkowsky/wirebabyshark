import pandas as pd

class PacketAnalyzer:
    def __init__(self, data):
        """
        Initialize the PacketAnalyzer with a dictionary or pandas DataFrame.
        """
        self.df = pd.DataFrame(data)
    
    def group_by_column(self, column_name):
        """
        Groups the DataFrame by a column and returns counts for each unique value.
        """
        if column_name in self.df.columns:
            return self.df.groupby(column_name).size().reset_index(name='count').sort_values(by='count', ascending=False)
        else:
            raise ValueError(f"Column '{column_name}' does not exist in the DataFrame.")

    def filter_by_column_value(self, column_name, value):
        """
        Filters the DataFrame by a column and value.
        """
        if column_name in self.df.columns:
            return self.df[self.df[column_name] == value]
        else:
            raise ValueError(f"Column '{column_name}' does not exist in the DataFrame.")

    def get_unique_values_in_column(self, column_name):
        """
        Returns unique values in a specified column.
        """
        if column_name in self.df.columns:
            return self.df[column_name].unique()
        else:
            raise ValueError(f"Column '{column_name}' does not exist in the DataFrame.")

    def display(self):
        """
        Displays the current DataFrame.
        """
        return self.df



# Create an instance of PacketAnalyzer
# analyzer = PacketAnalyzer(data)

# # Group by 'src' column and count records
# print("Grouped by 'src':")
# print(analyzer.group_by_column('src'))

# # Filter by a specific source IP
# print("\nFiltered by src='10.0.0.1':")
# print(analyzer.filter_by_column('src', '10.0.0.1'))

# # Get unique values in 'dst' column
# print("\nUnique values in 'dst':")
# print(analyzer.get_unique_values('dst'))

# # Display the current DataFrame
# print("\nCurrent DataFrame:")
# print(analyzer.display())
