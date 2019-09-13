-- Your SQL goes here

-- drop persistent_menu column on chatbots table
alter table chatbots drop column persistent_menu cascade;