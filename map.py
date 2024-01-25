import re
import sqlite3
import requests
import pycountry
import collections
from tqdm import tqdm
import cartopy.crs as ccrs
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import create_engine, Column, String, Float, Integer


max_workers = 10
log_file= "access.log"
db_file = "ip_geolocation.db"
api_token = "xxx"
#get api_token : https://ipinfo.io/account/home


Base = declarative_base()

class Geolocation(Base):
    __tablename__ = 'geolocations'
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True)  # 确保IP是唯一的
    country_name = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)

    def __init__(self, db_file=None, logfile=None, api_token=None, Session=None, **kwargs):
        self.db_file = db_file
        self.logfile = logfile
        self.api_token = api_token
        self.Session = Session
        super(Geolocation, self).__init__(**kwargs)

    def extract_ips(self):
        with open(self.logfile, 'r') as f:
            log_content = f.read()
        ips = set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', log_content))
        return list(ips)

    def is_valid_ip(self, ip):
        # 简单的正则表达式来匹配标准 IPv4 地址
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if pattern.match(ip):
            parts = ip.split('.')
            return all(0 <= int(part) < 256 for part in parts)
        return False

    def get_geolocation(self, session, ip, api_token):
        # 先从数据库中查找
        geolocation = session.query(Geolocation).filter_by(ip=ip).first()
        if geolocation:
            return geolocation
        # 没有找到则请求API
        GEOLOC_API_URL = f'http://ipinfo.io/{ip}/json?token={api_token}'
        response = requests.get(GEOLOC_API_URL)
        if response.status_code == 200:
            data = response.json()
            country_code = data.get('country', '')
            country_name = pycountry.countries.get(alpha_2=country_code).name if country_code else 'Unknown'
            loc = data.get('loc', '').split(',')
            if len(loc) == 2:
                latitude, longitude = map(float, loc)
                # 存储到数据库
                geolocation = Geolocation(ip=ip, country_name=country_name, latitude=latitude, longitude=longitude)
                session.add(geolocation)
                session.commit()
                return geolocation
        return None

    def worker(self, ip):
        with Session() as session:
            geolocation = self.get_geolocation(session, ip, self.api_token)
            if geolocation is not None:
                result = {
                    'id': geolocation.id,
                    'ip': geolocation.ip,
                    'country_name': geolocation.country_name,
                    'latitude': geolocation.latitude,
                    'longitude': geolocation.longitude
                }
                return result
            else:
                print(f"Geolocation not found for IP: {ip}")
                return None  # 或者返回一个包含默认值的字典

    def queryIP(self, ips, max_workers):
        valid_ips = [ip for ip in ips if self.is_valid_ip(ip)]  # Filter out invalid IPs
        invalid_ips = set(ips) - set(valid_ips)  # Identify the invalid IPs
        # Log or print the invalid IPs, if any
        if invalid_ips:
            print(f"Invalid IP addresses: {invalid_ips}")
        results = []  # Initialize an empty list for results
        # Create a thread pool and use tqdm to display the progress
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create a dictionary to map futures to IPs
            future_to_ip = {executor.submit(self.worker, ip): ip for ip in valid_ips}
            # Iterate over the futures as they complete and update the progress bar
            for future in tqdm(as_completed(future_to_ip), total=len(valid_ips), desc="Getting geolocations", colour='blue'):
                result = future.result()  # Get the result from the future
                if result is not None:
                    results.append(result)  # Add the result to the results list if it's not None
        return results


    def plot_heatmap(self):
        # 计算每个国家的IP计数
        country_counts = collections.Counter(loc['country_name'] for loc in locations if loc)
        # 分离国家和计数
        countries, counts = zip(*country_counts.items())
        # 绘制地图和热力图
        fig = plt.figure(figsize=(15, 10))
        ax = fig.add_subplot(1, 1, 1, projection=ccrs.PlateCarree())
        ax.stock_img()
        # Create a list of location tuples from the locations data
        locs = [(loc['longitude'], loc['latitude']) for loc in locations]
        # Calculate sizes for the scatter plot based on counts
        sizes = [country_counts[loc['country_name']] / max(counts) * 300 for loc in locations]
        # Ensure counts_array is the same length as locs for color mapping
        counts_array = [country_counts[loc['country_name']] for loc in locations]   
        # 以国家为键，收集每个国家的地理位置及其IP计数
        country_data = {}
        for loc in locations:
            if loc['country_name'] == 'Taiwan, Province of China':
                loc['country_name'] = 'China'
            country_name = loc['country_name']
            lat_lon = (loc['latitude'], loc['longitude'])
            if country_name not in country_data:
                country_data[country_name] = {'latitudes': [], 'longitudes': [], 'count': 0}
            country_data[country_name]['latitudes'].append(lat_lon[0])
            country_data[country_name]['longitudes'].append(lat_lon[1])
            country_data[country_name]['count'] += 1
        # 为每个国家准备热力圈大小和颜色数据
        sizes = []
        counts_array = []
        for data in country_data.values():
            count = data['count']
            num_locations = len(data['latitudes'])
            for _ in range(num_locations):
                sizes.append(count / max(counts) * 300)
                counts_array.append(count)
        # 绘制热力点
        locs = [(lat, lon) for data in country_data.values() for lat, lon in zip(data['latitudes'], data['longitudes'])]
        sc = ax.scatter([loc[1] for loc in locs], [loc[0] for loc in locs], s=sizes, c=counts_array, cmap='plasma', alpha=0.6, edgecolors='none', transform=ccrs.PlateCarree())
        # 定义欧洲小国家的集合
        small_european_countries = {'Albania', 'Andorra', 'Armenia', 'Austria', 'Azerbaijan', 'Belarus', 'Belgium',
            'Bosnia and Herzegovina', 'Bulgaria', 'Croatia', 'Cyprus', 'Czech Republic', 'Denmark',
            'Estonia', 'Finland', 'France', 'Georgia', 'Germany', 'Greece', 'Hungary', 'Iceland',
            'Ireland', 'Italy', 'Kazakhstan', 'Kosovo', 'Latvia', 'Liechtenstein', 'Lithuania',
            'Luxembourg', 'Malta', 'Moldova', 'Monaco', 'Montenegro', 'Netherlands', 'North Macedonia',
            'Norway', 'Poland', 'Portugal', 'Romania', 'Russia', 'San Marino', 'Serbia', 'Slovakia',
            'Slovenia', 'Spain', 'Sweden', 'Switzerland', 'Turkey', 'Ukraine', 'United Kingdom', 'Vatican City'}    
        # 初始化欧洲国家的数据
        europe_data = {'latitudes': [], 'longitudes': [], 'count': 0}
        # 处理其他国家的数据以及欧洲国家的汇总
        for country_name, data in country_data.items():
            if country_name in small_european_countries:
                # 汇总欧洲国家的数据
                europe_data['latitudes'].extend(data['latitudes'])
                europe_data['longitudes'].extend(data['longitudes'])
                europe_data['count'] += data['count']
            else:
                # 非欧洲国家添加标签
                avg_lat = sum(data['latitudes']) / len(data['latitudes'])
                avg_lon = sum(data['longitudes']) / len(data['longitudes'])
                plt.text(avg_lon, avg_lat, f"{country_name}\n({data['count']})", fontsize=9, ha='center', va='center', transform=ccrs.Geodetic())
        # 如果有欧洲国家的数据，添加"Europe"标签
        if europe_data['count'] > 0:
            avg_lat = sum(europe_data['latitudes']) / len(europe_data['latitudes'])
            avg_lon = sum(europe_data['longitudes']) / len(europe_data['longitudes'])
            plt.text(avg_lon, avg_lat, f"Europe\n({europe_data['count']})", fontsize=9, ha='center', va='center', transform=ccrs.Geodetic())    
        # 设置地图标题和其他属性
        plt.title('IP Locations Heatmap')
        plt.show()



# 创建数据库引擎，使用连接池
database_url = 'sqlite:///ip_geolocation.db'  #数据库URL
engine = create_engine(database_url, echo=False, connect_args={"check_same_thread": False})
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# 传入待分析日志文件及sqlite3数据库文件
ip_locator = Geolocation(db_file, log_file, api_token, Session)

# 提取IP地址
ips = ip_locator.extract_ips()  
#print(ips)

# 获取地理位置信息
locations = ip_locator.queryIP(ips, max_workers)
#print(locations)

# 绘制热力图
ip_locator.plot_heatmap()  
