#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <sstream>

using namespace std;

const string ORIGINAL_PLAINTEXT = "THE DEFINITION OF INDISTINGUISHABILITY IS SYNTACTICALLY ALMOST IDENTICAL TO THE ALTERNATE DEFINITION OF PERFECT SECRECY GIVEN AS DEFINITION TWO FOUR THIS SERVES TO HIGHLIGHT THE CLOSE CONNECTION BETWEEN THE TWO NOTIONS PERFECT SECRECY REQUIRES THAT THE PROBABILITY DISTRIBUTIONS OVER THE CIPHERTEXT SPACE CONDITIONED ON THE TRANSMISSION OF ANY TWO PLAINTEXT MESSAGES BE IDENTICAL WE CAN VIEW THIS FROM ANOTHER PERSPECTIVE AN ADVERSARY INTERCEPTING A CIPHERTEXT IS UNABLE TO DISTINGUISH WHETHER IT WAS THE ENCRYPTION OF THE FIRST MESSAGE OR THE SECOND MESSAGE";
const string KEY_CIPHER = "QWERTYUIOPASDFGHJKLZXCVBNM"; 

string encrypt_text(string pt) {
    string ct = "";
    for(char c : pt) {
        if(c >= 'A' && c <= 'Z') ct += KEY_CIPHER[c - 'A'];
        else ct += c;
    }
    return ct;
}

void frequency_analysis(const string& ct) {
    int counts[26] = {0};
    int total = 0;
    for(char c : ct) {
        if(c >= 'A' && c <= 'Z') { counts[c - 'A']++; total++; }
    }
    cout << "\n--- Letter Frequency ---\n";
    vector<pair<int, char>> freq;
    for(int i=0; i<26; i++) if(counts[i] > 0) freq.push_back({counts[i], i + 'A'});
    for(size_t i=0; i<freq.size(); i++) {
        for(size_t j=i+1; j<freq.size(); j++) {
            if(freq[i].first < freq[j].first) swap(freq[i], freq[j]);
        }
    }
    for(auto p : freq) {
        cout << p.second << ": " << p.first << " (" << ((double)p.first / total * 100.0) << "%)\n";
    }
}

void word_frequency_analysis(const string& ct) {
    cout << "\n--- Word Patterns ---\n";
    map<string, int> word_counts;
    stringstream ss(ct); string word;
    while(ss >> word) {
        string clean_word = "";
        for(char c : word) if(c >= 'A' && c <= 'Z') clean_word += c;
        if(clean_word.length() >= 1 && clean_word.length() <= 3) word_counts[clean_word]++;
    }
    for(int len=1; len<=3; len++) {
        for(auto const& [w, count] : word_counts) {
            if(w.length() == len && count > 1) cout << w << ": " << count << " times\n";
        }
    }
}

void apply_substitution(char mapping[26]) {
    char c_char, p_char;
    cout << "Ciphertext letter: "; cin >> c_char;
    cout << "Plaintext substitution (* to clear): "; cin >> p_char;
    if(toupper(c_char) >= 'A' && toupper(c_char) <= 'Z') {
        mapping[toupper(c_char) - 'A'] = tolower(p_char);
    }
}

void display_partial_plaintext(const string& ct, char mapping[26]) {
    cout << "\n--- Partial Plaintext ---\n";
    for(char c : ct) {
        if(c >= 'A' && c <= 'Z') {
            char sub = mapping[c - 'A'];
            cout << (sub != '*' ? sub : c);
        } else cout << c;
    }
    cout << "\n";
}

int main() {
    string ciphertext = encrypt_text(ORIGINAL_PLAINTEXT);
    char mapping[26];
    for(int i=0; i<26; i++) mapping[i] = '*';

    int choice = 0;
    while(choice != 5) {
        cout << "\n1. Freq Analysis\n2. Word Analysis\n3. Substitute\n4. Show Plaintext\n5. Exit\nChoice: ";
        cin >> choice;
        if(choice == 1) frequency_analysis(ciphertext);
        if(choice == 2) word_frequency_analysis(ciphertext);
        if(choice == 3) apply_substitution(mapping);
        if(choice == 4) display_partial_plaintext(ciphertext, mapping);
    }
    return 0;
}