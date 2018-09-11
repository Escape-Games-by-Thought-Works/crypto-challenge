require 'idea'

RSpec.describe IDEA do
  skip 'encrypts and decrypts a block' do
    idea = IDEA.new(0x08ab12edefba116234D081527a7b7301)

    input = [0x0123, 0x4567, 0x89ab, 0xcdef]
    result = idea.encrypt_block(input)

    expect(idea.decrypt_block(result)).to eq(input)
  end

  skip 'encrypts and decrypts a string' do
    idea = IDEA.new(0x08ab12edefba116234D081527a7b7301)

    result = idea.encrypt_string('some string with content')

    expect(result).to be_a(String)
    expect(result).not_to eq('some string with content')
    expect(idea.decrypt_string(result)).to eq('some string with content')
  end
end
