# IP Heat Map Generator

## Description

This Python script generates a heat map based on the geographic locations of IP addresses. It takes a list of IPs, validates them, retrieves their geolocation data, and then plots them on a map to visualize the distribution of the IP addresses across the globe.You can use this script to analyze any file containing IP addresses and then generate a corresponding heat map.

## Features

- **Local Database Integration**: Utilize a local database to store geolocation data, reducing the need for repeated API calls and enabling quicker access to previously queried IP address information.
- **Concurrent Processing**: Implement multi-threading with a configurable number of worker threads  to enable efficient and faster processing of large log files.
- **Visual Mapping**: Generate visual representations, such as maps or charts, to illustrate the origin of web visits and SSH login attempts, facilitating easy interpretation and analysis of traffic patterns.
- **Customizable Settings**: Configure various aspects of the script, including API tokens, the number of maximum workers, log file paths, and database file paths, to suit different analysis needs and environments.

## Usage

To use the IP Heat Map Generator, follow these steps:

1.Clone the repository to your local machine:

```bash
git clone https://github.com/Mr-Aur0ra/IPHeatMap.git
cd IPHeatMap
```

2.To run the IP Heat Map Generator, you need to have Python 3 installed on your machine. You can download it from [Python's official website](https://www.python.org/).

After installing Python, you need to install the required libraries. Navigate to the project directory and run the following command:

```bash
pip3 install -r requirements.txt
```

3.Create a file containing a list of IP addresses that you want to visualize.I recommend using it to Analyze the access logs of nginx/apache or SSH brute force logs. This project has a sample file `access.log`.

4.To configure the script, you can modify the following settings in `map.py`:

- `api_token`: Set your API token for the geolocation service. This is required to retrieve the geolocation data of the IP addresses found in your logs. You can get a free key from here: https://ipinfo.io/
- `max_workers`: Adjust the number of worker threads for parallel processing. This determines how many concurrent threads will be used to process the log data and fetch geolocation information, which can speed up the script if you have a large number of IP addresses to process.
- `log_file`: Specify the path to your web access log or SSH attempt log file or any other file containing IP addresses. The script will read this file to extract the IP addresses that need to be visualized.
- `db_file`: Set the path to your database file here. This could be a SQLite database file or similar, where the script stores IP address information. If not specified, the database file ip_geolocation.db will be generated by default.

5.Run the script with the following command:

```bash
python3 map.py
```

![demo](./img/demo.gif)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributions

Contributions are welcome! If you have any suggestions or improvements, please feel free to fork the repository and submit a pull request.

## Support

If you encounter any problems or have any questions, please open an issue on the project's GitHub page.