from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options

def error_handler(method):
  try:
    return method()
  except Exception:
    return False

def get_score(url_vector):
  # Configure headless Firefox
  options = Options()
  options.add_argument("-headless")

  # tell us what page we're looking at
  print("This is the checked URL:" + url_vector)

  # Initialize driver
  driver = webdriver.Firefox(options=options)

  # get the page
  driver.get(url_vector)
  
  # wait for javascript to load, what maybe 15 seconds
  WebDriverWait(driver, 15).until(EC.frame_to_be_available_and_switch_to_it((By.CLASS_NAME,"full-frame")))

# WebDriverWait(driver, 20).until(EC.visibility_of_element_located((By.XPATH, "//span[@class='c-hand text-warning']")))

  # print(driver.page_source)

  # check for the c-hand text-warning element and store it, if it exists
  # score = driver.find_element(By.CLASS_NAME, 'c-hand.text-warning')
  # if score_error_handler(driver.find_element(By.CLASS_NAME, 'c-hand.text-warning')):
  try:
    score = driver.find_element(By.CLASS_NAME, 'c-hand.text-warning')
  except:
    pass

  try:
    score = driver.find_element(By.CLASS_NAME, 'c-hand.text-error')
  except:
    pass
  
  # if error_handler(driver.find_element(By.CLASS_NAME, 'c-hand.text-warning')):
    
  # score = score_error_handler(driver.find_element(By.CLASS_NAME, 'c-hand.text-error'))

  
  # print(driver.page_source)

  # return the value
  print(score.get_attribute("innerText"))
  result = score.get_attribute("innerText")
  
  # quit the driver, important for performance!
  
  driver.quit()
  
  return result

source_file = "vectors"
destination_file = "scores"

# Open the source file for reading and the destination file for writing
with open(source_file, 'r') as source, open(destination_file, 'w') as destination:
  # Loop through each line in the source file
  for line in source:
    # Read the line and remove any trailing newline character
    line = line.rstrip()
    # build the URL
      
    url = "https://www.first.org/cvss/calculator/4.0#" + line
      
    # call the web scraper and get the value back 
     
    calc_value = get_score(url)
      
    # Write the vector and score to the destination file
    destination.write(calc_value + " " + line + "\n")

