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

    def filter_by_column_values(self, column_name, values):
        """
        Filters the DataFrame by a column and a list of values.
        """
        if column_name in self.df.columns:
            print(f"Filtering out values: {values} from column: {column_name}")
            self.df = self.df[self.df[column_name].isin(values)]
            # print(f"Number of rows before filtering: {len(self.df)}")
            print(f"Number of rows after filtering: {len(self.df)}")
            return self.df
        else:
            raise ValueError(f"Column '{column_name}' does not exist in the DataFrame.")

    def filter_by_column_values_neg(self, column_name, values):
        """
        Filters the DataFrame by a column and a list of values.
        """
        if column_name in self.df.columns:
            print(f"Filtering out values: {values} from column: {column_name}")
            self.df = self.df[~self.df[column_name].isin(values)]
            # print(f"Number of rows before filtering: {len(self.df)}")
            print(f"Number of rows after filtering: {len(self.df)}")
            return self.df
        else:
            raise ValueError(f"Column '{column_name}' does not exist in the DataFrame.")

    def filter_by_column_range(self, column_name, value_range):
        """
        Filters the DataFrame by a column and a range of values.
        """
        if column_name in self.df.columns:
            if isinstance(value_range, list) and len(value_range) == 2:
                print(f"Filtering out values: {value_range} from column: {column_name}")
                self.df = self.df[(self.df[column_name] >= int(value_range[0])) & (self.df[column_name] <= int(value_range[1]))]

                # print(f"Number of rows before filtering: {len(self.df)}")
                print(f"Number of rows after filtering: {len(self.df)}")
                return self.df
            else:
                raise ValueError(f"Value range for column '{column_name}' must be a list of two elements.")
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

